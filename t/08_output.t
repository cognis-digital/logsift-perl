use strict; use warnings;
use Test::More;
use JSON::PP;
use Logsift::Output qw(render);

my @findings = (
    { type => 'brute_force', severity => 2, src => '10.0.0.9', count => 6,
      window => '-', evidence => '6 failed logins from 10.0.0.9',
      attack => 'T1110.001', extra => { failures => 6, distinct_users => 1 } },
    { type => 'rate_spike', severity => 4, src => '-', count => 50,
      window => '1000-1060', evidence => '50 events in 60s window' },
);
my $stats = { total_events => 100, matched_events => 6, sources => 1, by_severity => { 2 => 6, 6 => 94 } };
my @top = ({ signature => 'x <NUM>', count => 10 });

# --- JSON valid + structure ---
my $json = render(\@findings, $stats, \@top, 'json');
my $doc = eval { decode_json($json) };
ok($doc, 'json output parses');
is($doc->{tool}, 'logsift', 'tool key');
is(scalar @{ $doc->{findings} }, 2, 'two findings in json');
is($doc->{findings}[0]{attack}, 'T1110.001', 'attack tag survives json');
ok($doc->{stats}{total_events} == 100, 'stats in json');

# --- NDJSON: one valid JSON object per line ---
my $nd = render(\@findings, $stats, \@top, 'ndjson');
my @lines = split /\n/, $nd;
is(scalar @lines, 2, 'ndjson has one line per finding');
my $l0 = eval { decode_json($lines[0]) };
ok($l0, 'ndjson line 0 parses');
is($l0->{type}, 'brute_force', 'ndjson line 0 type');

# --- CEF well-formed ---
my $cef = render(\@findings, $stats, \@top, 'cef');
my @cl = split /\n/, $cef;
is(scalar @cl, 2, 'two cef lines');
like($cl[0], qr/^CEF:0\|Cognis\|logsift\|[\d.]+\|100\|SSH.auth brute force\|9\|/, 'cef header well-formed');
like($cl[0], qr/\bsrc=10\.0\.0\.9\b/, 'cef src extension');
like($cl[0], qr/cs1=T1110\.001/, 'cef carries ATT&CK technique');

# --- text summary ---
my $txt = render(\@findings, $stats, \@top, 'text');
like($txt, qr/brute_force/, 'text lists finding');
like($txt, qr/ATT&CK T1110\.001/, 'text shows attack tag');
like($txt, qr/2 finding\(s\)/, 'text finding count');

# unknown format dies
eval { render(\@findings, $stats, \@top, 'zzz'); };
like($@, qr/unknown output format/, 'unknown format rejected');

done_testing();
