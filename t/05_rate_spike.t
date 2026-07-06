use strict; use warnings;
use Test::More;
use Logsift::Detectors;

# Build a controlled event stream by feeding events with known timestamps.
# 10 buckets with 2 events each (baseline), 1 bucket with 50 events (spike).
my $e = Logsift::Detectors->new(bucket => 60, spike_sigma => 3.0, fail_threshold => 999999);
my $base = 1700000000;
for my $b (0..9) {
    for (1..2) { $e->feed({ ts => $base + $b*60, message => "ok $b", severity => 6 }); }
}
for (1..50) { $e->feed({ ts => $base + 20*60, message => "boom", severity => 6 }); }

my @f = $e->finish;
my ($spike) = grep { $_->{type} eq 'rate_spike' } @f;
ok($spike, 'rate_spike detected');
is($spike->{count}, 50, 'spike bucket count = 50');
like($spike->{evidence}, qr/baseline mean=/, 'reports baseline mean');
like($spike->{evidence}, qr/sd=/, 'reports baseline stddev');

# verify the math: 11 buckets, counts = ten 2s + one 50
my @counts = (2)x10; push @counts, 50;
my $n=@counts; my $sum=0; $sum+=$_ for @counts; my $mean=$sum/$n;
my $var=0; $var+=($_-$mean)**2 for @counts; $var/=$n; my $sd=sqrt($var);
ok(50 > $mean + 3*$sd, 'spike exceeds mean+3sd (sanity of test data)');
ok(2 <= $mean + 3*$sd, 'baseline buckets do NOT exceed threshold');

# flat data -> no spike (stddev 0)
my $e2 = Logsift::Detectors->new(bucket => 60, fail_threshold => 999999);
for my $b (0..9) { $e2->feed({ ts => $base + $b*60, message => "x", severity => 6 }); }
my @f2 = $e2->finish;
ok(!(grep { $_->{type} eq 'rate_spike' } @f2), 'flat rate -> no spike');

done_testing();
