use strict; use warnings;
use Test::More;
use Logsift::Detectors;

# templating: numbers and IPs become placeholders
is(Logsift::Detectors::signature('Failed password for root from 10.0.0.9 port 22 ssh2'),
   'Failed password for root from <IP> port <NUM> ssh<NUM>', 'IP + port + version digit templated');
is(Logsift::Detectors::signature('request took 1234ms id 5678'),
   'request took <NUM>ms id <NUM>', 'numbers templated');
is(Logsift::Detectors::signature('token abcdef0123456789abcdef'),
   'token <HASH>', 'long hex -> HASH');

# two identical-shape lines collapse to one signature
my $e = Logsift::Detectors->new(rare_max => 1, fail_threshold => 999999);
$e->feed({ message => 'user 111 logged in', severity => 6 });
$e->feed({ message => 'user 222 logged in', severity => 6 });   # same signature
$e->feed({ message => 'CATASTROPHIC kernel panic 0x1', severity => 2 }); # rare (1x)
my @f = $e->finish;
my ($rare) = grep { $_->{type} eq 'rare_signature' } @f;
ok($rare, 'rare_signature detected');
like($rare->{evidence}, qr/kernel panic/, 'rare finding is the panic line');
ok(!(grep { $_->{extra}{signature} =~ /logged in/ } grep { $_->{type} eq 'rare_signature' } @f),
   'the twice-seen signature is NOT rare (seen 2 > rare_max 1)');

# top_signatures reports the frequent one
my @top = $e->top_signatures;
is($top[0]{signature}, 'user <NUM> logged in', 'top signature is the collapsed frequent one');
is($top[0]{count}, 2, 'top signature count = 2');

done_testing();
