#!/usr/bin/env perl
use strict;
use warnings;
use FindBin qw($RealBin);
use lib "$RealBin/lib";
use Logsift::Parser  qw(parse_line detect_format);
use Logsift::Detectors ();
use Logsift::Output  qw(render);

our $VERSION = '2.0.0';

# ---------------------------------------------------------------------------
# CLI parsing (hand-rolled; core-only, no Getopt dependency surprises).
# ---------------------------------------------------------------------------
my %opt = (
    format        => 'json',    # output format
    input_format  => 'auto',    # parser
    fail_threshold  => 5,
    spray_threshold => 5,
    scan_paths      => 15,
    error_burst     => 20,
    rare_max        => 2,
    bucket          => 60,
    spike_sigma     => 3.0,
);
my @files;
my @allowlist;
my ($since, $until);

sub parse_time_spec {
    my ($s) = @_;
    return undef unless defined $s;
    return $s + 0 if $s =~ /^\d+$/;                     # epoch
    if ($s =~ /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})$/) {
        require POSIX;
        return POSIX::mktime($6,$5,$4,$3,$2-1,$1-1900);
    }
    die "logsift: cannot parse time '$s' (use epoch or YYYY-MM-DDTHH:MM:SS)\n";
}

sub usage {
    print <<"EOF";
logsift $VERSION - dependency-free log triage & SIEM-ready findings

Usage:
  logsift [options] FILE [FILE...]      # .gz auto-detected
  cat auth.log | logsift [options] -    # read stdin

Input:
  --format-in NAME   parser: auto|json|syslog3164|syslog5424|nginx|apache|generic
  --since SPEC       only events at/after SPEC (epoch or YYYY-MM-DDTHH:MM:SS)
  --until SPEC       only events at/before SPEC

Output:
  --format NAME      json (default) | ndjson | cef | text

Detectors / thresholds:
  --fail-threshold N   brute-force: min failed logins per source IP (5)
  --spray-threshold N  spray: min distinct users per source IP (5)
  --scan-paths N       http scan: min distinct paths per IP (15)
  --error-burst N      http error burst: min 4xx/5xx per IP (20)
  --rare-max N         rare signature: report signatures seen <= N times (2)
  --bucket SECONDS     rate-spike time bucket width (60)
  --spike-sigma F      rate-spike threshold = mean + F*stddev (3.0)
  --allowlist-ip IP    suppress detections for this IP (repeatable)

Other:
  -h, --help           this help
  --version            print version

Exit: 0 clean, 2 findings present, 1 error.
Docs: perldoc logsift.pl
EOF
    exit 0;
}

while (@ARGV) {
    my $a = shift @ARGV;
    if    ($a eq '--format')          { $opt{format} = shift @ARGV; }
    elsif ($a eq '--format-in')       { $opt{input_format} = shift @ARGV; }
    elsif ($a eq '--fail-threshold')  { $opt{fail_threshold}  = 0 + shift @ARGV; }
    elsif ($a eq '--spray-threshold') { $opt{spray_threshold} = 0 + shift @ARGV; }
    elsif ($a eq '--scan-paths')      { $opt{scan_paths}      = 0 + shift @ARGV; }
    elsif ($a eq '--error-burst')     { $opt{error_burst}     = 0 + shift @ARGV; }
    elsif ($a eq '--rare-max')        { $opt{rare_max}        = 0 + shift @ARGV; }
    elsif ($a eq '--bucket')          { my $b = shift @ARGV; $b =~ s/s$//; $opt{bucket} = 0 + $b; }
    elsif ($a eq '--spike-sigma')     { $opt{spike_sigma}     = 0 + shift @ARGV; }
    elsif ($a eq '--allowlist-ip')    { push @allowlist, shift @ARGV; }
    elsif ($a eq '--since')           { $since = parse_time_spec(shift @ARGV); }
    elsif ($a eq '--until')           { $until = parse_time_spec(shift @ARGV); }
    elsif ($a eq '--version')         { print "logsift $VERSION\n"; exit 0; }
    elsif ($a eq '-h' or $a eq '--help') { usage(); }
    elsif ($a eq '-')                 { push @files, '-'; }
    elsif ($a =~ /^--/)               { print STDERR "logsift: unknown option $a\n"; exit 1; }
    else                              { push @files, $a; }
}

my %valid_out = map { $_ => 1 } qw(json ndjson cef text);
unless ($valid_out{ $opt{format} }) {
    print STDERR "logsift: unknown output format '$opt{format}'\n"; exit 1;
}

my $engine = Logsift::Detectors->new(
    fail_threshold  => $opt{fail_threshold},
    spray_threshold => $opt{spray_threshold},
    scan_paths      => $opt{scan_paths},
    error_burst     => $opt{error_burst},
    rare_max        => $opt{rare_max},
    bucket          => $opt{bucket},
    spike_sigma     => $opt{spike_sigma},
    allowlist       => \@allowlist,
);

# ---------------------------------------------------------------------------
# Open a source: '-' = stdin, *.gz = gunzip stream, else plain file.
# Returns a filehandle (streamed, never slurped).
# ---------------------------------------------------------------------------
sub open_source {
    my ($path) = @_;
    if ($path eq '-') { return \*STDIN; }
    if ($path =~ /\.gz$/i) {
        require IO::Uncompress::Gunzip;
        no warnings 'once';
        my $z = IO::Uncompress::Gunzip->new($path)
            or die "logsift: cannot gunzip $path: $IO::Uncompress::Gunzip::GunzipError\n";
        return $z;
    }
    open(my $fh, '<', $path) or die "logsift: cannot open $path: $!\n";
    return $fh;
}

sub feed_fh {
    my ($fh) = @_;
    while (defined(my $line = <$fh>)) {
        my $ev = parse_line($line, $opt{input_format});
        if (defined $ev->{ts}) {
            next if defined $since && $ev->{ts} < $since;
            next if defined $until && $ev->{ts} > $until;
        }
        $engine->feed($ev);
    }
}

eval {
    if (@files) {
        for my $f (@files) {
            my $fh = open_source($f);
            feed_fh($fh);
            close($fh) unless $f eq '-';
        }
    } else {
        feed_fh(\*STDIN);
    }
    1;
} or do {
    print STDERR $@;
    exit 1;
};

my @findings  = $engine->finish;
my $stats     = $engine->stats;
my @top_sigs  = $engine->top_signatures;

print render(\@findings, $stats, \@top_sigs, $opt{format});

exit(@findings ? 2 : 0);

__END__

=head1 NAME

logsift - dependency-free log triage & SIEM-ready detection engine

=head1 SYNOPSIS

  logsift [options] FILE [FILE...]
  cat /var/log/auth.log | logsift -
  logsift --format cef --format-in nginx access.log

=head1 DESCRIPTION

SOC and DFIR analysts drown in raw logs. C<logsift> is a fast, pure-Perl
first-pass triage tool: it parses common log formats into a normalized event
model, runs a battery of streaming detectors, and emits SIEM-ready findings.

It has zero non-core dependencies (JSON::PP and IO::Uncompress::Gunzip ship
with Perl 5.14+), streams input line-by-line (never slurps), and returns a
CI-friendly exit code.

=head2 Input formats (--format-in)

=over 4

=item * B<auto> - per-line format detection (default)

=item * B<syslog3164> - RFC 3164 BSD syslog ("Mon DD HH:MM:SS host prog[pid]: msg")

=item * B<syslog5424> - RFC 5424 syslog ("<PRI>VERSION TS HOST APP PROCID MSGID SD MSG")

=item * B<nginx> / B<apache> - combined access logs

=item * B<json> - one JSON object per line (JSON::PP)

=item * B<generic> - bare lines (e.g. raw OpenSSH output)

=back

=head2 Detectors

=over 4

=item * B<brute_force> - many failed logins from one source IP (ATT&CK T1110.001)

=item * B<password_spray> - one IP against many distinct users (ATT&CK T1110.003)

=item * B<http_scan> - one IP requesting many distinct paths

=item * B<http_error_burst> - burst of 4xx/5xx from one IP

=item * B<rate_spike> - time buckets exceeding mean + N*stddev of event rate

=item * B<rare_signature> - message templates ("signatures") seen <= N times

=back

=head2 Output formats (--format)

C<json> (default), C<ndjson> (one finding per line), C<cef>
(ArcSight Common Event Format), C<text> (human summary table).

=head2 MITRE ATT&CK

Findings are tagged with ATT&CK technique IDs B<only> where the mapping is
defensible (brute force, spraying, valid-account bursts). Generic spikes and
rare signatures are deliberately left untagged. See F<docs/ARCHITECTURE.md>.

=head1 EXIT STATUS

  0  clean (no findings)
  2  one or more findings
  1  error (bad option, unreadable file)

=head1 LICENSE

COCL 1.0. Commercial use: licensing@cognis.digital

=cut
