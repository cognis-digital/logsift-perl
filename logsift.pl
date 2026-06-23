#!/usr/bin/env perl
# logsift — auth-log brute-force / password-spray detector (Perl)
# Part of the Cognis Neural Suite. Single-purpose, JSON-out, CI-tested.
#
# Reads syslog/auth.log-style lines from FILE or stdin and flags:
#   - brute force : many failed logins from ONE source IP
#   - spray       : ONE source IP failing against MANY distinct users
# Recognizes OpenSSH "Failed password for [invalid user] <user> from <ip>".
#
# Usage:
#   logsift /var/log/auth.log
#   journalctl -u ssh | logsift -
# Options:
#   --fail-threshold N   min failures from one IP to flag brute force (default 5)
#   --spray-threshold N  min distinct users from one IP to flag spray  (default 5)
#
# Output: JSON summary on stdout. Exit 2 if any finding, else 0.
use strict;
use warnings;

my $fail_threshold  = 5;
my $spray_threshold = 5;
my @files;
while (@ARGV) {
    my $a = shift @ARGV;
    if    ($a eq '--fail-threshold')  { $fail_threshold  = shift @ARGV; }
    elsif ($a eq '--spray-threshold') { $spray_threshold = shift @ARGV; }
    elsif ($a eq '-h' or $a eq '--help') {
        print STDERR "usage: logsift [--fail-threshold N] [--spray-threshold N] FILE|-\n"; exit 0;
    }
    else { push @files, $a; }
}

my (%fail_by_ip, %users_by_ip, $total_fail, $total_lines);

sub feed {
    my ($fh) = @_;
    while (my $line = <$fh>) {
        $total_lines++;
        # OpenSSH failed password
        if ($line =~ /Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})/) {
            my ($user, $ip) = ($1, $2);
            $fail_by_ip{$ip}++;
            $users_by_ip{$ip}{$user} = 1;
            $total_fail++;
        }
        # generic "authentication failure ... rhost=<ip> user=<user>"
        elsif ($line =~ /authentication failure/ && $line =~ /rhost=(\d{1,3}(?:\.\d{1,3}){3})/) {
            my $ip = $1;
            my $user = ($line =~ /user=(\S+)/) ? $1 : '?';
            $fail_by_ip{$ip}++;
            $users_by_ip{$ip}{$user} = 1;
            $total_fail++;
        }
    }
}

if (@files) {
    for my $f (@files) {
        if ($f eq '-') { feed(\*STDIN); next; }
        open(my $fh, '<', $f) or do { print STDERR "logsift: cannot open $f: $!\n"; exit 1; };
        feed($fh);
        close($fh);
    }
} else {
    feed(\*STDIN);
}

my @findings;
for my $ip (sort { $fail_by_ip{$b} <=> $fail_by_ip{$a} } keys %fail_by_ip) {
    my $fails = $fail_by_ip{$ip};
    my $nusers = scalar keys %{ $users_by_ip{$ip} };
    if ($fails >= $fail_threshold) {
        push @findings, { type => 'brute_force', ip => $ip, failures => $fails, distinct_users => $nusers };
    }
    if ($nusers >= $spray_threshold) {
        push @findings, { type => 'password_spray', ip => $ip, failures => $fails, distinct_users => $nusers };
    }
}

# tiny dependency-free JSON emitter
sub jstr { my $s = shift; $s =~ s/(["\\])/\\$1/g; return "\"$s\""; }
sub emit_finding {
    my $f = shift;
    return sprintf('{"type":%s,"ip":%s,"failures":%d,"distinct_users":%d}',
        jstr($f->{type}), jstr($f->{ip}), $f->{failures}, $f->{distinct_users});
}
print '{"tool":"logsift",';
printf '"lines_scanned":%d,"failed_logins":%d,"sources":%d,', $total_lines, ($total_fail//0), scalar(keys %fail_by_ip);
print '"findings":[' . join(',', map { emit_finding($_) } @findings) . "]}\n";

exit(@findings ? 2 : 0);
