FROM perl:5.38-slim
# logsift needs only core Perl (JSON::PP, IO::Uncompress::Gunzip ship with core).
LABEL org.opencontainers.image.title="logsift" \
      org.opencontainers.image.description="Dependency-free log triage & SIEM-ready detection (Perl)" \
      org.opencontainers.image.licenses="LicenseRef-COCL-1.0"

WORKDIR /opt/logsift
COPY logsift.pl ./logsift.pl
COPY lib ./lib

# smoke test at build time
RUN perl -c logsift.pl && perl -Ilib -e 'use Logsift::Parser; use Logsift::Detectors; use Logsift::Output; print "modules OK\n"'

# read logs from stdin by default
ENTRYPOINT ["perl", "/opt/logsift/logsift.pl"]
CMD ["--help"]
