# logsift — pure Perl, no build step. Targets: test, check, demos, bench, install.
PREFIX ?= /usr/local
PERL   ?= perl

.PHONY: all test check demos bench install clean help

all: check test

help:
	@echo "targets: check (perl -c) | test (prove) | demos | bench | install | clean"

# syntax-check every Perl file
check:
	$(PERL) -c logsift.pl
	$(PERL) -Ilib -c lib/Logsift/Parser.pm
	$(PERL) -Ilib -c lib/Logsift/Detectors.pm
	$(PERL) -Ilib -c lib/Logsift/Output.pm

# run the test suite (prove if available, else a direct loop)
test:
	@if command -v prove >/dev/null 2>&1 && prove --version >/dev/null 2>&1; then \
		prove -Ilib -It t/ ; \
	else \
		ok=1; for f in t/*.t; do echo "== $$f =="; $(PERL) -Ilib -It $$f || ok=0; done; \
		[ $$ok -eq 1 ] || { echo "TESTS FAILED"; exit 1; }; \
	fi

demos:
	sh examples/run_all.sh

bench:
	$(PERL) bench/bench.pl 200000

install:
	sh install.sh $(PREFIX)

clean:
	rm -f t/*_*.log t/*.gz examples/logs/*.tmp bench/bench_*.log
