package Logsift::Parser;
# Logsift::Parser — turn a raw log line into a normalized event hashref.
#
# Normalized event schema (all keys optional except 'raw'):
#   raw        original line (chomped)
#   ts         epoch seconds (integer) if a timestamp could be parsed
#   ts_str     the raw timestamp substring, if any
#   host       hostname
#   program    program / app name (e.g. sshd, nginx)
#   pid        process id
#   severity   normalized severity 0..7 (syslog scale; lower = worse)
#   sev_name   normalized severity name (EMERG..DEBUG)
#   message    the free-text message portion
#   src_ip     source IP if extracted
#   user       username if extracted
#   http_status HTTP status code (int) for access logs
#   http_path  request path for access logs
#   http_method HTTP method
#   fmt        which parser produced the event
#
# Pure Perl 5, core modules only.

use strict;
use warnings;
use JSON::PP ();

use Exporter 'import';
our @EXPORT_OK = qw(parse_line detect_format normalize_severity);

# ---- month table for RFC3164 / syslog timestamps -------------------------
my %MON = (
    Jan => 0, Feb => 1, Mar => 2, Apr => 3, May => 4, Jun => 5,
    Jul => 6, Aug => 7, Sep => 8, Oct => 9, Nov => 10, Dec => 11,
);

# Syslog severity scale (RFC 5424): 0 EMERG .. 7 DEBUG
my @SEV_NAME = qw(EMERG ALERT CRIT ERROR WARNING NOTICE INFO DEBUG);
my %SEV_BY_NAME = (
    EMERG => 0, EMERGENCY => 0, PANIC => 0,
    ALERT => 1,
    CRIT => 2, CRITICAL => 2, FATAL => 2,
    ERR => 3, ERROR => 3,
    WARN => 4, WARNING => 4,
    NOTICE => 5,
    INFO => 6, INFORMATIONAL => 6,
    DEBUG => 7, TRACE => 7,
);

# Map an arbitrary level word to the normalized syslog scale.
sub normalize_severity {
    my ($word) = @_;
    return (6, 'INFO') unless defined $word;
    my $u = uc $word;
    $u =~ s/[^A-Z]//g;
    if (exists $SEV_BY_NAME{$u}) {
        my $n = $SEV_BY_NAME{$u};
        return ($n, $SEV_NAME[$n]);
    }
    return (6, 'INFO');
}

# Decode the RFC5424 PRI value (facility*8 + severity).
sub _pri_to_sev {
    my ($pri) = @_;
    my $sev = $pri % 8;
    return ($sev, $SEV_NAME[$sev]);
}

# ---- timestamp parsers ---------------------------------------------------

# RFC3164: "Jun 22 10:00:01"  (no year -> assume current year)
sub _parse_rfc3164_ts {
    my ($mon, $day, $h, $m, $s) = @_;
    return undef unless exists $MON{$mon};
    my @lt = localtime(time);
    my $year = $lt[5];    # years since 1900
    require POSIX;
    # timelocal-free: use POSIX::mktime
    my $epoch = POSIX::mktime($s, $m, $h, $day, $MON{$mon}, $year);
    return $epoch;
}

# RFC5424 / ISO8601: 2026-06-22T10:00:01(.fff)?(Z|+hh:mm)?
sub _parse_iso_ts {
    my ($y, $mo, $d, $h, $mi, $s, $tz) = @_;
    require POSIX;
    my $epoch = POSIX::mktime($s, $mi, $h, $d, $mo - 1, $y - 1900);
    return undef unless defined $epoch;
    # If an explicit offset/Z was given, mktime treated fields as local;
    # correct back to true epoch. We treat the value as UTC when tz is Z/+00.
    if (defined $tz && $tz ne '') {
        # figure local offset at this instant
        my @g = gmtime($epoch);
        my @l = localtime($epoch);
        my $local_off = POSIX::mktime(@l[0..5]) - POSIX::mktime(@g[0..5]);
        my $want_off = 0;
        if ($tz =~ /^([+-])(\d{2}):?(\d{2})$/) {
            $want_off = ($1 eq '-' ? -1 : 1) * ($2 * 3600 + $3 * 60);
        }
        $epoch += $local_off - $want_off;
    }
    return $epoch;
}

my $JP = JSON::PP->new->utf8(0);

# ---- format detection ----------------------------------------------------
# Returns one of: json syslog5424 syslog3164 nginx apache ssh generic
sub detect_format {
    my ($line) = @_;
    return 'json' if $line =~ /^\s*\{.*\}\s*$/;
    return 'syslog5424' if $line =~ /^<\d{1,3}>\d\s/;           # <PRI>VERSION
    # nginx/apache combined: IP - user [date] "METHOD path proto" status size
    return 'nginx' if $line =~ /^\S+ \S+ \S+ \[[^\]]+\] "\S+ \S+[^"]*" \d{3} /;
    # RFC3164: "Mon DD HH:MM:SS host program"
    return 'syslog3164' if $line =~ /^[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\s/;
    return 'generic';
}

# ---- individual parsers --------------------------------------------------

sub _parse_json {
    my ($line) = @_;
    my $ev = { raw => $line, fmt => 'json' };
    my $obj = eval { $JP->decode($line) };
    return $ev unless ref $obj eq 'HASH';
    # common key aliases
    for my $k (qw(timestamp time ts @timestamp)) {
        if (defined $obj->{$k}) { $ev->{ts_str} = $obj->{$k}; last; }
    }
    if (defined $ev->{ts_str}) {
        if ($ev->{ts_str} =~ /^\d+(\.\d+)?$/) {
            $ev->{ts} = int($ev->{ts_str});
        } elsif ($ev->{ts_str} =~
            /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?/) {
            $ev->{ts} = _parse_iso_ts($1,$2,$3,$4,$5,$6,$7);
        }
    }
    for my $k (qw(level severity lvl loglevel)) {
        if (defined $obj->{$k}) {
            my ($n,$name) = normalize_severity($obj->{$k});
            $ev->{severity} = $n; $ev->{sev_name} = $name; last;
        }
    }
    $ev->{message} = $obj->{message} // $obj->{msg} // $obj->{log} // '';
    $ev->{host}    = $obj->{host} // $obj->{hostname} if defined($obj->{host}) || defined($obj->{hostname});
    $ev->{program} = $obj->{program} // $obj->{logger_name} // $obj->{app} if defined($obj->{program}) || defined($obj->{logger_name}) || defined($obj->{app});
    for my $k (qw(src_ip src client clientip client_ip remote_addr ip)) {
        if (defined $obj->{$k} && $obj->{$k} =~ /(\d{1,3}(?:\.\d{1,3}){3})/) {
            $ev->{src_ip} = $1; last;
        }
    }
    $ev->{user} = $obj->{user} // $obj->{username} // $obj->{usr} if defined($obj->{user}) || defined($obj->{username}) || defined($obj->{usr});
    if (defined $obj->{status} && $obj->{status} =~ /^\d{3}$/) { $ev->{http_status} = $obj->{status}+0; }
    $ev->{http_path} = $obj->{path} // $obj->{request} // $obj->{url} if defined($obj->{path}) || defined($obj->{request}) || defined($obj->{url});
    $ev->{severity} //= 6; $ev->{sev_name} //= 'INFO';
    return $ev;
}

sub _parse_syslog5424 {
    my ($line) = @_;
    my $ev = { raw => $line, fmt => 'syslog5424' };
    # <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP [SD] SP MSG
    if ($line =~ /^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$/) {
        my ($pri, undef, $ts, $host, $app, $procid, undef, $rest) = ($1,$2,$3,$4,$5,$6,$7,$8);
        my ($sev, $name) = _pri_to_sev($pri);
        $ev->{severity} = $sev; $ev->{sev_name} = $name;
        $ev->{host} = $host unless $host eq '-';
        $ev->{program} = $app unless $app eq '-';
        $ev->{pid} = $procid if $procid =~ /^\d+$/;
        $ev->{ts_str} = $ts unless $ts eq '-';
        if ($ts =~ /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?/) {
            $ev->{ts} = _parse_iso_ts($1,$2,$3,$4,$5,$6,$7);
        }
        # strip structured-data block [ ... ] at start of rest
        $rest =~ s/^\[[^\]]*\]\s*//;
        $ev->{message} = $rest;
        _extract_common($ev, $rest);
    }
    $ev->{severity} //= 6; $ev->{sev_name} //= 'INFO';
    return $ev;
}

sub _parse_syslog3164 {
    my ($line) = @_;
    my $ev = { raw => $line, fmt => 'syslog3164' };
    # Mon DD HH:MM:SS host program[pid]: message
    if ($line =~ /^([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+([^:\[\s]+)(?:\[(\d+)\])?:\s*(.*)$/) {
        my ($mon,$day,$h,$m,$s,$host,$prog,$pid,$msg) = ($1,$2,$3,$4,$5,$6,$7,$8,$9);
        $ev->{ts_str} = "$mon $day $h:$m:$s";
        $ev->{ts} = _parse_rfc3164_ts($mon,$day,$h,$m,$s);
        $ev->{host} = $host;
        $ev->{program} = $prog;
        $ev->{pid} = $pid if defined $pid;
        $ev->{message} = $msg;
        _extract_common($ev, $msg);
    } elsif ($line =~ /^([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+(.*)$/) {
        my ($mon,$day,$h,$m,$s,$host,$msg) = ($1,$2,$3,$4,$5,$6,$7);
        $ev->{ts_str} = "$mon $day $h:$m:$s";
        $ev->{ts} = _parse_rfc3164_ts($mon,$day,$h,$m,$s);
        $ev->{host} = $host;
        $ev->{message} = $msg;
        _extract_common($ev, $msg);
    }
    $ev->{severity} //= 6; $ev->{sev_name} //= 'INFO';
    return $ev;
}

# Apache/Nginx "combined" access log.
sub _parse_access {
    my ($line, $fmt) = @_;
    my $ev = { raw => $line, fmt => $fmt };
    if ($line =~ /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)[^"]*"\s+(\d{3})\s+(\S+)/) {
        my ($ip,$user,$date,$method,$path,$status,$size) = ($1,$2,$3,$4,$5,$6,$7);
        $ev->{src_ip} = $ip if $ip =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;
        $ev->{user} = $user unless $user eq '-';
        $ev->{http_method} = $method;
        $ev->{http_path} = $path;
        $ev->{http_status} = $status + 0;
        # date: 22/Jun/2026:10:00:01 +0000
        if ($date =~ m{^(\d{1,2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?}) {
            my ($d,$mon,$y,$h,$mi,$s,$tz) = ($1,$2,$3,$4,$5,$6,$7);
            $ev->{ts_str} = $date;
            if (exists $MON{$mon}) {
                $tz =~ s/([+-]\d{2})(\d{2})/$1:$2/ if defined $tz;
                $ev->{ts} = _parse_iso_ts($y, $MON{$mon}+1, $d, $h, $mi, $s, $tz);
            }
        }
        # infer severity from status
        my $st = $ev->{http_status};
        if    ($st >= 500) { ($ev->{severity},$ev->{sev_name}) = (3,'ERROR'); }
        elsif ($st >= 400) { ($ev->{severity},$ev->{sev_name}) = (4,'WARNING'); }
        else               { ($ev->{severity},$ev->{sev_name}) = (6,'INFO'); }
        $ev->{message} = "$method $path $status";
    }
    $ev->{severity} //= 6; $ev->{sev_name} //= 'INFO';
    return $ev;
}

# Bare OpenSSH / generic line with no syslog prefix.
sub _parse_generic {
    my ($line) = @_;
    my $ev = { raw => $line, fmt => 'generic', message => $line, severity => 6, sev_name => 'INFO' };
    _extract_common($ev, $line);
    return $ev;
}

# Extract src_ip / user / auth semantics from a message body. Mutates $ev.
sub _extract_common {
    my ($ev, $msg) = @_;
    if ($msg =~ /Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})/) {
        $ev->{user} = $1; $ev->{src_ip} = $2; $ev->{auth_fail} = 1;
    } elsif ($msg =~ /Invalid user (\S+) from (\d{1,3}(?:\.\d{1,3}){3})/) {
        $ev->{user} = $1; $ev->{src_ip} = $2; $ev->{auth_fail} = 1;
    } elsif ($msg =~ /authentication failure/) {
        $ev->{auth_fail} = 1;
        $ev->{src_ip} = $1 if $msg =~ /rhost=(\d{1,3}(?:\.\d{1,3}){3})/;
        $ev->{user}   = $1 if $msg =~ /user=(\S+)/;
    } elsif ($msg =~ /Accepted (?:password|publickey) for (\S+) from (\d{1,3}(?:\.\d{1,3}){3})/) {
        $ev->{user} = $1; $ev->{src_ip} = $2; $ev->{auth_ok} = 1;
    }
    if (!defined $ev->{src_ip} && $msg =~ /(?:from|rhost=|client )(\d{1,3}(?:\.\d{1,3}){3})/) {
        $ev->{src_ip} = $1;
    }
    return $ev;
}

# ---- public entry --------------------------------------------------------
# parse_line($line, $format) — $format one of the detect_format names or 'auto'
sub parse_line {
    my ($line, $format) = @_;
    $line = '' unless defined $line;
    chomp $line;
    $format = 'auto' unless defined $format;
    my $fmt = ($format eq 'auto') ? detect_format($line) : $format;

    if    ($fmt eq 'json')       { return _parse_json($line); }
    elsif ($fmt eq 'syslog5424') { return _parse_syslog5424($line); }
    elsif ($fmt eq 'syslog3164') { return _parse_syslog3164($line); }
    elsif ($fmt eq 'nginx' || $fmt eq 'apache') { return _parse_access($line, $fmt); }
    elsif ($fmt eq 'ssh' || $fmt eq 'generic')  { return _parse_generic($line); }
    else { return _parse_generic($line); }
}

1;
