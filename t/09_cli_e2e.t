use strict; use warnings;
use Test::More;
use FindBin qw($RealBin);
use JSON::PP;
use IO::Compress::Gzip qw(gzip);

my $prog = "$RealBin/../logsift.pl";
my $auth = "$RealBin/../examples/logs/auth.log";
my $perl = $^X;

sub run {
    my (@args) = @_;
    my $cmd = join(' ', map { qq{"$_"} } ($perl, "-I$RealBin/../lib", $prog, @args));
    my $out = `$cmd`;
    return ($out, $? >> 8);
}

SKIP: {
    skip "example auth.log missing", 6 unless -e $auth;

    # JSON on auth.log: brute + spray + exit 2
    my ($out, $code) = run('--format', 'json', $auth);
    my $doc = eval { decode_json($out) };
    ok($doc, 'e2e json parses');
    ok((grep { $_->{type} eq 'brute_force' } @{$doc->{findings}}), 'e2e brute_force present');
    ok((grep { $_->{type} eq 'password_spray' } @{$doc->{findings}}), 'e2e spray present');
    is($code, 2, 'exit 2 when findings');

    # text format runs
    my ($t, $tc) = run('--format', 'text', $auth);
    like($t, qr/logsift/, 'text output header');
    is($tc, 2, 'text exit 2');
}

# clean input -> exit 0
# (repeat a benign line enough that its signature is common, not rare)
{
    my $tmp = "$RealBin/clean_$$.log";
    open my $fh, '>', $tmp or die $!;
    for my $i (1..10) {
        my $ss = sprintf('%02d', $i);
        print $fh "Jun 22 10:00:$ss h sshd[1]: Accepted password for alice from 10.0.0.7 port 22 ssh2\n";
    }
    close $fh;
    my ($out, $code) = run($tmp);
    is($code, 0, 'clean repeated benign lines -> exit 0');
    unlink $tmp;
}

# bad option -> exit 1
{
    my ($out, $code) = run('--nonsense');
    is($code, 1, 'bad option -> exit 1');
}

# stdin via '-'
{
    my $line = "Jun 22 10:00:01 h sshd[1]: Failed password for root from 5.5.5.5 port 22 ssh2\n" x 6;
    my $tmp = "$RealBin/stdin_$$.log";
    open my $fh, '>', $tmp; print $fh $line; close $fh;
    my $out = `"$perl" "-I$RealBin/../lib" "$prog" --format json - < "$tmp"`;
    my $doc = eval { decode_json($out) };
    ok(($doc && grep { $_->{type} eq 'brute_force' } @{$doc->{findings}}), 'stdin brute_force detected');
    unlink $tmp;
}

# gzip support
SKIP: {
    my $gz = "$RealBin/g_$$.log.gz";
    my $blob = join('', map { "Jun 22 10:00:0$_ h sshd[1]: Failed password for root from 7.7.7.7 port 22 ssh2\n" } 1..6);
    gzip(\$blob => $gz) or skip "gzip failed", 1;
    my ($out, $code) = run('--format', 'json', $gz);
    my $doc = eval { decode_json($out) };
    ok(($doc && grep { $_->{type} eq 'brute_force' } @{$doc->{findings}}), 'gzip .gz input detected brute_force');
    unlink $gz;
}

# since/until filtering: exclude the brute-force window entirely
SKIP: {
    skip "example auth.log missing", 1 unless -e $auth;
    # auth.log brute window is ~2026-06-22 10:00; filter to a far-future window
    my ($out, $code) = run('--since', '2030-01-01T00:00:00', '--format', 'json', $auth);
    my $doc = eval { decode_json($out) };
    is($code, 0, '--since future -> no findings, exit 0');
}

done_testing();
