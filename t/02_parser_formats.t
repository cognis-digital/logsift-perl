use strict; use warnings;
use Test::More;
use Logsift::Parser qw(parse_line detect_format);

# --- format auto-detection ---
is(detect_format('{"a":1}'), 'json', 'json detected');
is(detect_format('<34>1 2026-06-22T14:00:01Z host app 1 - - hi'), 'syslog5424', 'rfc5424 detected');
is(detect_format('Jun 22 10:00:01 host prog: msg'), 'syslog3164', 'rfc3164 detected');
is(detect_format('1.2.3.4 - - [22/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 10'), 'nginx', 'nginx detected');
is(detect_format('just some text'), 'generic', 'generic fallback');

# --- RFC5424 ---
my $s = parse_line('<34>1 2026-06-22T14:00:01.003Z host01 sshd 4321 - - hello world', 'auto');
is($s->{fmt}, 'syslog5424', 'rfc5424 fmt');
is($s->{host}, 'host01', 'rfc5424 host');
is($s->{program}, 'sshd', 'rfc5424 app');
is($s->{pid}, 4321, 'rfc5424 procid');
is($s->{severity}, 2, 'rfc5424 severity from PRI 34 (34%8=2 CRIT)');
is($s->{sev_name}, 'CRIT', 'rfc5424 sev name');
ok(defined $s->{ts}, 'rfc5424 timestamp parsed to epoch');

# --- nginx combined ---
my $n = parse_line('45.146.164.110 - - [22/Jun/2026:12:00:01 +0000] "GET /.env HTTP/1.1" 404 162 "-" "zgrab"', 'auto');
is($n->{fmt}, 'nginx', 'nginx fmt');
is($n->{src_ip}, '45.146.164.110', 'nginx src ip');
is($n->{http_method}, 'GET', 'nginx method');
is($n->{http_path}, '/.env', 'nginx path');
is($n->{http_status}, 404, 'nginx status');
is($n->{severity}, 4, 'nginx 404 -> WARNING severity');
ok(defined $n->{ts}, 'nginx timestamp parsed');

# --- JSON ---
my $j = parse_line('{"timestamp":"2026-06-22T13:00:09Z","level":"ERROR","message":"db refused","src_ip":"10.1.2.3","status":500}', 'auto');
is($j->{fmt}, 'json', 'json fmt');
is($j->{severity}, 3, 'json ERROR -> severity 3');
is($j->{src_ip}, '10.1.2.3', 'json src_ip');
is($j->{http_status}, 500, 'json status');
ok(defined $j->{ts}, 'json epoch parsed from iso');

# json with epoch timestamp
my $je = parse_line('{"time":1700000000,"level":"warn","msg":"x"}', 'json');
is($je->{ts}, 1700000000, 'json epoch timestamp');
is($je->{severity}, 4, 'json warn -> 4');

done_testing();
