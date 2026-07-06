use strict; use warnings;
use Test::More;
use Logsift::Detectors;

# ATT&CK mapping table is correct and conservative.
is($Logsift::Detectors::ATTACK{brute_force}, 'T1110.001', 'brute -> T1110.001');
is($Logsift::Detectors::ATTACK{password_spray}, 'T1110.003', 'spray -> T1110.003');
is($Logsift::Detectors::ATTACK{valid_burst}, 'T1078', 'valid burst -> T1078');
ok(!exists $Logsift::Detectors::ATTACK{rate_spike}, 'rate_spike has NO attack tag (honest)');
ok(!exists $Logsift::Detectors::ATTACK{rare_signature}, 'rare_signature has NO attack tag (honest)');
ok(!exists $Logsift::Detectors::ATTACK{http_scan}, 'http_scan has NO attack tag (honest)');

# severity counting via stats()
my $e = Logsift::Detectors->new(fail_threshold => 999999);
$e->feed({ severity => 2, message => 'a' });
$e->feed({ severity => 2, message => 'b' });
$e->feed({ severity => 6, message => 'c' });
my $s = $e->stats;
is($s->{total_events}, 3, 'total events counted');
is($s->{by_severity}{2}, 2, 'two sev-2 events counted');
is($s->{by_severity}{6}, 1, 'one sev-6 event counted');

done_testing();
