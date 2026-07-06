use strict; use warnings;
use Test::More;
use Logsift::Parser qw(parse_line);
use Logsift::Detectors;

my $e = Logsift::Detectors->new(scan_paths => 15, error_burst => 20);
for my $i (1..25) {
    my $ts = sprintf('22/Jun/2026:12:%02d:%02d +0000', int($i/60), $i%60);
    $e->feed(parse_line(qq{45.1.2.3 - - [$ts] "GET /path$i HTTP/1.1" 404 10 "-" "s"}, 'auto'));
}
my @f = $e->finish;
my ($scan) = grep { $_->{type} eq 'http_scan' } @f;
ok($scan, 'http_scan detected');
is($scan->{count}, 25, 'scan distinct paths = 25');
is($scan->{src}, '45.1.2.3', 'scan src ip');

my ($burst) = grep { $_->{type} eq 'http_error_burst' } @f;
ok($burst, 'http_error_burst detected');
is($burst->{count}, 25, '25 error responses');

# below thresholds
my $e2 = Logsift::Detectors->new(scan_paths => 15, error_burst => 20);
for my $i (1..5) {
    my $ts = sprintf('22/Jun/2026:12:00:%02d +0000', $i);
    $e2->feed(parse_line(qq{9.9.9.9 - - [$ts] "GET /p$i HTTP/1.1" 200 10 "-" "s"}, 'auto'));
}
my @f2 = $e2->finish;
ok(!(grep { $_->{type} =~ /^http_/ } @f2), '5 clean 200s -> no http findings');

done_testing();
