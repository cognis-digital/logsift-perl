use strict; use warnings;
use Test::More;
use Logsift::Parser qw(normalize_severity);

my %expect = (
    EMERG => 0, alert => 1, crit => 2, critical => 2, fatal => 2,
    err => 3, ERROR => 3, warn => 4, WARNING => 4, notice => 5,
    info => 6, DEBUG => 7, trace => 7,
);
for my $w (sort keys %expect) {
    my ($n, $name) = normalize_severity($w);
    is($n, $expect{$w}, "severity '$w' -> $expect{$w}");
}
# unknown -> INFO(6)
my ($un) = normalize_severity('bogus');
is($un, 6, 'unknown level -> INFO(6)');
# undef -> INFO(6)
my ($ud) = normalize_severity(undef);
is($ud, 6, 'undef level -> INFO(6)');

done_testing();
