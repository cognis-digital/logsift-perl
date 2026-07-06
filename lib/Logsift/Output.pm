package Logsift::Output;
# Logsift::Output — render findings + stats in several formats:
#   json   one JSON object (pretty-ish, stable key order via JSON::PP canonical)
#   ndjson one JSON object per finding (streaming/SIEM ingest)
#   cef    ArcSight Common Event Format (one CEF line per finding)
#   text   human-readable summary table
#
# Pure Perl 5; JSON::PP is core since 5.14.

use strict;
use warnings;
use JSON::PP ();

use Exporter 'import';
our @EXPORT_OK = qw(render);

our $VERSION = '2.0.0';

# CEF severity is 0..10; map from syslog 0..7 (lower syslog = worse).
sub _cef_severity {
    my ($syslog_sev) = @_;
    $syslog_sev = 6 unless defined $syslog_sev;
    my %map = (0=>10,1=>10,2=>9,3=>7,4=>5,5=>3,6=>2,7=>1);
    return $map{$syslog_sev} // 5;
}

# CEF field escaping: backslash and pipe in header; = and \n in extension.
sub _cef_header_esc { my $s = shift // ''; $s =~ s/([\\|])/\\$1/g; $s =~ s/\n/ /g; return $s; }
sub _cef_ext_esc    { my $s = shift // ''; $s =~ s/([\\=])/\\$1/g; $s =~ s/\n/ /g; return $s; }

# Map a finding type -> CEF signatureId + name.
my %CEF_SIG = (
    brute_force      => [100, 'SSH/auth brute force'],
    password_spray   => [101, 'Password spray'],
    http_scan        => [200, 'HTTP path scanning'],
    http_error_burst => [201, 'HTTP error burst'],
    rate_spike       => [300, 'Event rate spike'],
    rare_signature   => [400, 'Rare log signature'],
);

sub _render_cef {
    my ($findings) = @_;
    my @out;
    for my $f (@$findings) {
        my $sig = $CEF_SIG{ $f->{type} } || [999, $f->{type}];
        my $name = _cef_header_esc($sig->[1]);
        my $sev  = _cef_severity($f->{severity});
        # CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
        my $hdr = sprintf('CEF:0|Cognis|logsift|%s|%d|%s|%d|',
            $VERSION, $sig->[0], $name, $sev);
        my @ext;
        push @ext, 'src=' . _cef_ext_esc($f->{src}) if defined $f->{src} && $f->{src} ne '-';
        push @ext, 'cnt=' . _cef_ext_esc($f->{count}) if defined $f->{count};
        push @ext, 'msg=' . _cef_ext_esc($f->{evidence}) if defined $f->{evidence};
        push @ext, 'cs1Label=technique cs1=' . _cef_ext_esc($f->{attack}) if $f->{attack};
        push @ext, 'cs2Label=window cs2=' . _cef_ext_esc($f->{window})
            if defined $f->{window} && $f->{window} ne '-';
        push @out, $hdr . join(' ', @ext);
    }
    return join("\n", @out) . (@out ? "\n" : '');
}

sub _finding_to_hash {
    my ($f) = @_;
    my %h = (
        type     => $f->{type},
        severity => $f->{severity},
        src      => $f->{src},
        count    => $f->{count},
        window   => $f->{window},
        evidence => $f->{evidence},
    );
    $h{attack} = $f->{attack} if $f->{attack};
    if ($f->{extra} && %{ $f->{extra} }) { $h{extra} = $f->{extra}; }
    return \%h;
}

sub _render_json {
    my ($findings, $stats, $top_sigs) = @_;
    my $jp = JSON::PP->new->canonical(1)->pretty(1)->space_before(0);
    my $doc = {
        tool     => 'logsift',
        version  => $VERSION,
        stats    => $stats,
        top_signatures => $top_sigs,
        findings => [ map { _finding_to_hash($_) } @$findings ],
    };
    return $jp->encode($doc);
}

sub _render_ndjson {
    my ($findings) = @_;
    my $jp = JSON::PP->new->canonical(1);   # compact, one line each
    my @out;
    for my $f (@$findings) {
        push @out, $jp->encode(_finding_to_hash($f));
    }
    return join("\n", @out) . (@out ? "\n" : '');
}

sub _render_text {
    my ($findings, $stats, $top_sigs) = @_;
    my @out;
    push @out, 'logsift ' . $VERSION;
    push @out, sprintf('  events scanned : %d', $stats->{total_events} // 0);
    push @out, sprintf('  auth failures  : %d from %d source(s)',
        $stats->{matched_events} // 0, $stats->{sources} // 0);
    if ($stats->{by_severity} && %{ $stats->{by_severity} }) {
        my @sev = map { "$_=$stats->{by_severity}{$_}" }
                  sort { $a <=> $b } keys %{ $stats->{by_severity} };
        push @out, '  by severity    : ' . join(' ', @sev);
    }
    push @out, '';
    if (@$findings) {
        push @out, sprintf('%-18s %-6s %-16s %-8s %s',
            'TYPE','SEV','SOURCE','COUNT','EVIDENCE');
        push @out, ('-' x 78);
        for my $f (@$findings) {
            push @out, sprintf('%-18s %-6d %-16s %-8s %s',
                $f->{type}, $f->{severity}, ($f->{src}//'-'),
                ($f->{count}//'-'), ($f->{evidence}//''));
            push @out, sprintf('%40s ATT&CK %s', '', $f->{attack}) if $f->{attack};
        }
        push @out, '';
        push @out, sprintf('%d finding(s).', scalar @$findings);
    } else {
        push @out, 'No findings.';
    }
    if ($top_sigs && @$top_sigs) {
        push @out, '';
        push @out, 'Top signatures:';
        push @out, sprintf('  %5d  %s', $_->{count}, $_->{signature}) for @$top_sigs;
    }
    return join("\n", @out) . "\n";
}

# render(\@findings, \%stats, \@top_sigs, $format)
sub render {
    my ($findings, $stats, $top_sigs, $format) = @_;
    $format ||= 'json';
    if    ($format eq 'json')   { return _render_json($findings, $stats, $top_sigs); }
    elsif ($format eq 'ndjson') { return _render_ndjson($findings); }
    elsif ($format eq 'cef')    { return _render_cef($findings); }
    elsif ($format eq 'text')   { return _render_text($findings, $stats, $top_sigs); }
    else { die "unknown output format: $format\n"; }
}

1;
