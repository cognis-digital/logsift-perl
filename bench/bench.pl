#!/usr/bin/env perl
# bench.pl — honest throughput benchmark for logsift.
#
# Generates a synthetic auth-style log of N lines (mix of benign + attack
# traffic), runs logsift over it, and reports lines/sec. Prints a machine
# label so numbers are reproducible and honestly attributable.
#
# Usage: perl bench/bench.pl [LINES]   (default 200000)
use strict;
use warnings;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";
use Logsift::Parser qw(parse_line);
use Logsift::Detectors;
use Time::HiRes qw(time);
use Config;

my $N = $ARGV[0] || 200_000;

# --- generate a temp log ---
my $tmp = "$RealBin/bench_$$.log";
open(my $out, '>', $tmp) or die $!;
my @users = qw(root admin oracle test git ubuntu deploy postgres alice bob);
my @ips   = map { "203.0.113.$_" } (1..40);
for my $i (1 .. $N) {
    my $sec = $i % 60;
    my $min = int($i / 60) % 60;
    my $hr  = int($i / 3600) % 24;
    my $u = $users[$i % @users];
    my $ip = $ips[$i % @ips];
    if ($i % 7 == 0) {
        printf $out "Jun 22 %02d:%02d:%02d web01 sshd[%d]: Accepted password for %s from %s port 22 ssh2\n",
            $hr,$min,$sec,$i,$u,$ip;
    } else {
        printf $out "Jun 22 %02d:%02d:%02d web01 sshd[%d]: Failed password for invalid user %s from %s port %d ssh2\n",
            $hr,$min,$sec,$i,$u,$ip,40000+$i;
    }
}
close $out;

# --- time an in-process parse+detect pass (pure engine throughput) ---
my $engine = Logsift::Detectors->new;
open(my $in, '<', $tmp) or die $!;
my $t0 = time();
my $lines = 0;
while (defined(my $l = <$in>)) {
    $engine->feed(parse_line($l, 'auto'));
    $lines++;
}
my @f = $engine->finish;
my $dt = time() - $t0;
close $in;
unlink $tmp;

my $rate = $dt > 0 ? $lines / $dt : 0;

printf "logsift benchmark\n";
printf "  perl        : %s\n", sprintf('%vd', $^V);
printf "  os/arch     : %s\n", $Config{archname};
printf "  lines       : %d\n", $lines;
printf "  findings    : %d\n", scalar @f;
printf "  wall time   : %.3f s\n", $dt;
printf "  throughput  : %.0f lines/sec\n", $rate;
