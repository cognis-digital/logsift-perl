use strict; use warnings;
use Test::More;
use Logsift::Parser qw(parse_line);

# generic bare OpenSSH line
my $ev = parse_line('Jun 22 10:00:01 host sshd[1]: Failed password for invalid user admin from 10.0.0.9 port 22 ssh2', 'auto');
is($ev->{fmt}, 'syslog3164', 'ssh line detected as rfc3164');
is($ev->{program}, 'sshd', 'program parsed');
is($ev->{pid}, 1, 'pid parsed');
is($ev->{src_ip}, '10.0.0.9', 'src ip extracted');
is($ev->{user}, 'admin', 'user extracted');
ok($ev->{auth_fail}, 'auth_fail flagged');

my $ok = parse_line('Jun 22 10:01:05 host sshd[2]: Accepted password for alice from 198.51.100.7 port 22 ssh2', 'auto');
ok($ok->{auth_ok}, 'accepted flagged as auth_ok');
is($ok->{user}, 'alice', 'accepted user parsed');

my $pam = parse_line('Jun 22 10:02:00 host sshd[3]: pam_unix(sshd:auth): authentication failure; rhost=192.0.2.44 user=admin', 'auto');
ok($pam->{auth_fail}, 'pam authentication failure flagged');
is($pam->{src_ip}, '192.0.2.44', 'pam rhost extracted');
is($pam->{user}, 'admin', 'pam user extracted');

done_testing();
