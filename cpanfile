# logsift uses ONLY core Perl modules — this cpanfile documents that fact.
# Everything below ships with Perl 5.14+ (no external CPAN install required).
requires 'perl', '5.014';

requires 'JSON::PP';                 # core since 5.14
requires 'IO::Uncompress::Gunzip';   # core (IO-Compress) — .gz support
requires 'IO::Compress::Gzip';       # core — used by the test suite only
requires 'FindBin';                  # core
requires 'POSIX';                    # core — timestamp math
requires 'Time::HiRes';              # core — benchmark timing
requires 'Config';                   # core — machine label in bench

on 'test' => sub {
    requires 'Test::More';           # core
};
