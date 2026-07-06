use strict; use warnings;
use Test::More;
use Logsift::Parser qw(parse_line);
use Logsift::Detectors;

sub findings_for {
    my ($lines, %opt) = @_;
    my $e = Logsift::Detectors->new(%opt);
    $e->feed(parse_line($_, 'auto')) for @$lines;
    return [ $e->finish ];
}

# brute force: 6 fails one IP one user -> brute_force, no spray (threshold 5)
my @brute = map { "Jun 22 10:00:0$_ h sshd[1]: Failed password for root from 10.0.0.9 port 22 ssh2" } (1..6);
my $f = findings_for(\@brute, spray_threshold => 5);
my ($bf) = grep { $_->{type} eq 'brute_force' } @$f;
ok($bf, 'brute_force detected');
is($bf->{count}, 6, 'brute count = 6');
is($bf->{attack}, 'T1110.001', 'brute attack tag T1110.001');
ok(!(grep { $_->{type} eq 'password_spray' } @$f), 'no spray (single user)');

# spray: one IP, 6 distinct users
my @users = qw(a b c d e f);
my @spray = map { "Jun 22 11:00:0$_ h sshd[1]: Failed password for $users[$_-1] from 203.0.113.55 port 40 ssh2" } (1..6);
my $sf = findings_for(\@spray);
my ($sp) = grep { $_->{type} eq 'password_spray' } @$sf;
ok($sp, 'password_spray detected');
is($sp->{count}, 6, 'spray distinct users = 6');
is($sp->{attack}, 'T1110.003', 'spray attack tag T1110.003');

# below threshold -> nothing
my @few = map { "Jun 22 10:00:0$_ h sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2" } (1..3);
my $nf = findings_for(\@few);
ok(!(grep { $_->{type} eq 'brute_force' } @$nf), '3 fails below threshold -> no brute');

# allowlist suppresses
my $af = findings_for(\@brute, allowlist => ['10.0.0.9']);
ok(!(grep { $_->{type} eq 'brute_force' } @$af), 'allowlisted IP suppressed');

done_testing();
