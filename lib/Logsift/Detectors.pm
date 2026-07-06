package Logsift::Detectors;
# Logsift::Detectors — run detection passes over a stream of normalized events.
#
# A detector engine is a stateful object: feed it events one at a time
# (streaming, O(1)-ish memory per source), then call finish() to get findings.
#
# Findings share a normalized schema:
#   type        detector id (brute_force, password_spray, http_scan,
#               http_error_burst, rate_spike, rare_signature)
#   severity    normalized syslog severity (0..7, lower = worse)
#   src         source identifier (IP or '-')
#   count       primary count
#   window      human window / context string (optional)
#   evidence    short sample string
#   attack      MITRE ATT&CK technique id (optional, only where honest)
#   extra       hashref of detector-specific fields
#
# Pure Perl 5, core modules only.

use strict;
use warnings;

use Exporter 'import';
our @EXPORT_OK = qw(new);

# MITRE ATT&CK mappings that are actually defensible for these signals.
# Deliberately conservative: generic spikes / rare signatures get NO tag.
our %ATTACK = (
    brute_force    => 'T1110.001',   # Brute Force: Password Guessing
    password_spray => 'T1110.003',   # Brute Force: Password Spraying
    valid_burst    => 'T1078',       # Valid Accounts (successful-auth burst)
);

sub new {
    my ($class, %opt) = @_;
    my $self = {
        # thresholds
        fail_threshold    => $opt{fail_threshold}    // 5,
        spray_threshold   => $opt{spray_threshold}   // 5,
        scan_paths        => $opt{scan_paths}        // 15,
        error_burst       => $opt{error_burst}       // 20,
        rare_max          => $opt{rare_max}          // 2,
        top_signatures    => $opt{top_signatures}    // 5,
        bucket            => $opt{bucket}            // 60,   # seconds
        spike_sigma       => $opt{spike_sigma}       // 3.0,
        allowlist         => { map { $_ => 1 } @{ $opt{allowlist} || [] } },
        # state
        fail_by_ip        => {},
        users_by_ip       => {},
        accept_by_ip      => {},
        paths_by_ip       => {},
        http_err_by_ip    => {},
        buckets           => {},   # bucket_index => count
        sig_count         => {},   # signature => count
        sig_sample        => {},   # signature => example message
        total_events      => 0,
        matched_events    => 0,
        by_severity       => {},
    };
    return bless $self, $class;
}

# Template-ize a message into a stable signature (Drain-lite).
sub signature {
    my ($msg) = @_;
    return '' unless defined $msg;
    my $s = $msg;
    $s =~ s/\b(?:\d{1,3}\.){3}\d{1,3}\b/<IP>/g;                 # IPv4
    $s =~ s/\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b/<MAC>/g;   # MAC
    $s =~ s/\b[0-9a-fA-F]{16,}\b/<HASH>/g;                      # long hex
    $s =~ s{\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\b}{<TS>}g; # iso ts
    $s =~ s/\bport \d+/port <NUM>/g;
    $s =~ s/\d+/<NUM>/g;                                        # any digit run
    $s =~ s/\s+/ /g;
    $s =~ s/^\s+|\s+$//g;
    return $s;
}

sub _bucket_index {
    my ($self, $ts) = @_;
    return undef unless defined $ts;
    return int($ts / $self->{bucket});
}

# Feed one normalized event.
sub feed {
    my ($self, $ev) = @_;
    $self->{total_events}++;
    my $sev = defined $ev->{severity} ? $ev->{severity} : 6;
    $self->{by_severity}{$sev}++;

    my $ip = $ev->{src_ip};
    my $allowed = ($ip && $self->{allowlist}{$ip}) ? 1 : 0;

    # rate buckets (all events with a timestamp)
    if (defined $ev->{ts}) {
        my $b = $self->_bucket_index($ev->{ts});
        $self->{buckets}{$b}++;
    }

    # log-signature templating (on the message)
    if (defined $ev->{message} && length $ev->{message}) {
        my $sig = signature($ev->{message});
        if (length $sig) {
            $self->{sig_count}{$sig}++;
            $self->{sig_sample}{$sig} //= $ev->{message};
        }
    }

    return if $allowed;

    # auth failures -> brute/spray
    if ($ev->{auth_fail} && $ip) {
        $self->{fail_by_ip}{$ip}++;
        $self->{users_by_ip}{$ip}{ $ev->{user} // '?' } = 1;
        $self->{matched_events}++;
    }
    if ($ev->{auth_ok} && $ip) {
        $self->{accept_by_ip}{$ip}++;
    }

    # http anomalies
    if (defined $ev->{http_status} && $ip) {
        if (defined $ev->{http_path}) {
            $self->{paths_by_ip}{$ip}{ $ev->{http_path} } = 1;
        }
        if ($ev->{http_status} >= 400) {
            $self->{http_err_by_ip}{$ip}++;
        }
    }
    return;
}

# Produce findings.
sub finish {
    my ($self) = @_;
    my @f;

    # --- brute force + password spray ---
    for my $ip (sort { $self->{fail_by_ip}{$b} <=> $self->{fail_by_ip}{$a} }
                keys %{ $self->{fail_by_ip} }) {
        my $fails  = $self->{fail_by_ip}{$ip};
        my $nusers = scalar keys %{ $self->{users_by_ip}{$ip} };
        if ($fails >= $self->{fail_threshold}) {
            push @f, {
                type => 'brute_force', severity => 2, src => $ip,
                count => $fails, window => '-',
                evidence => "$fails failed logins from $ip",
                attack => $ATTACK{brute_force},
                extra => { failures => $fails, distinct_users => $nusers },
            };
        }
        if ($nusers >= $self->{spray_threshold}) {
            push @f, {
                type => 'password_spray', severity => 2, src => $ip,
                count => $nusers, window => '-',
                evidence => "$ip attempted $nusers distinct users",
                attack => $ATTACK{password_spray},
                extra => { failures => $fails, distinct_users => $nusers },
            };
        }
    }

    # --- http scan (one IP hitting many distinct paths) ---
    for my $ip (sort { scalar(keys %{$self->{paths_by_ip}{$b}}) <=> scalar(keys %{$self->{paths_by_ip}{$a}}) }
                keys %{ $self->{paths_by_ip} }) {
        my $np = scalar keys %{ $self->{paths_by_ip}{$ip} };
        next unless $np >= $self->{scan_paths};
        push @f, {
            type => 'http_scan', severity => 4, src => $ip,
            count => $np, window => '-',
            evidence => "$ip requested $np distinct paths",
            extra => { distinct_paths => $np },
        };
    }

    # --- http error burst (many 4xx/5xx from one IP) ---
    for my $ip (sort { $self->{http_err_by_ip}{$b} <=> $self->{http_err_by_ip}{$a} }
                keys %{ $self->{http_err_by_ip} }) {
        my $n = $self->{http_err_by_ip}{$ip};
        next unless $n >= $self->{error_burst};
        push @f, {
            type => 'http_error_burst', severity => 4, src => $ip,
            count => $n, window => '-',
            evidence => "$ip generated $n HTTP 4xx/5xx responses",
            extra => { error_responses => $n },
        };
    }

    # --- rate spike (bucket count > mean + N*stddev) ---
    my @counts = values %{ $self->{buckets} };
    if (@counts >= 3) {
        my $n = scalar @counts;
        my $sum = 0; $sum += $_ for @counts;
        my $mean = $sum / $n;
        my $var = 0; $var += ($_ - $mean) ** 2 for @counts;
        $var /= $n;
        my $sd = sqrt($var);
        my $thresh = $mean + $self->{spike_sigma} * $sd;
        for my $b (sort { $self->{buckets}{$b} <=> $self->{buckets}{$a} }
                   keys %{ $self->{buckets} }) {
            my $c = $self->{buckets}{$b};
            last if $c <= $thresh;
            next if $sd == 0;
            my $start = $b * $self->{bucket};
            push @f, {
                type => 'rate_spike', severity => 4, src => '-',
                count => $c,
                window => sprintf('%d-%d', $start, $start + $self->{bucket}),
                evidence => sprintf('%d events in %ds window (baseline mean=%.1f sd=%.1f)',
                                    $c, $self->{bucket}, $mean, $sd),
                extra => {
                    bucket_start => $start,
                    bucket_seconds => $self->{bucket},
                    baseline_mean => sprintf('%.2f', $mean),
                    baseline_stddev => sprintf('%.2f', $sd),
                    sigma => $self->{spike_sigma},
                },
            };
        }
    }

    # --- rare signatures ---
    for my $sig (sort { $self->{sig_count}{$a} <=> $self->{sig_count}{$b} or $a cmp $b }
                 keys %{ $self->{sig_count} }) {
        my $c = $self->{sig_count}{$sig};
        last if $c > $self->{rare_max};
        push @f, {
            type => 'rare_signature', severity => 5, src => '-',
            count => $c, window => '-',
            evidence => $self->{sig_sample}{$sig},
            extra => { signature => $sig, occurrences => $c },
        };
    }

    return @f;
}

# Top-N frequent signatures (for the summary, not a finding).
sub top_signatures {
    my ($self) = @_;
    my @sigs = sort { $self->{sig_count}{$b} <=> $self->{sig_count}{$a} or $a cmp $b }
               keys %{ $self->{sig_count} };
    my $n = $self->{top_signatures};
    @sigs = @sigs[0 .. ($n-1 < $#sigs ? $n-1 : $#sigs)] if @sigs;
    return map { { signature => $_, count => $self->{sig_count}{$_} } } @sigs;
}

sub stats {
    my ($self) = @_;
    return {
        total_events   => $self->{total_events},
        matched_events => $self->{matched_events},
        sources        => scalar keys %{ $self->{fail_by_ip} },
        by_severity    => { %{ $self->{by_severity} } },
    };
}

1;
