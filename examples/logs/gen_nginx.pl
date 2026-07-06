#!/usr/bin/env perl
# Generates examples/logs/nginx-access.log: a path-scanning IP + benign traffic.
use strict; use warnings;
my @paths = qw(/admin /wp-login.php /.env /phpmyadmin /config.php /.git/config
  /backup.zip /shell.php /xmlrpc.php /wp-admin /login /api/v1/users
  /server-status /.aws/credentials /vendor/phpunit /solr/admin /cgi-bin/test
  /actuator/env /console /debug/vars /jenkins /manager/html /struts2
  /uploads/x.jsp /db.sql);
my $t = 0;
for my $p (@paths) {
    $t++;
    my $ts = sprintf('22/Jun/2026:12:%02d:%02d +0000', int($t/60), $t%60);
    print qq{45.146.164.110 - - [$ts] "GET $p HTTP/1.1" 404 162 "-" "zgrab/0.x"\n};
}
for my $i (1..10) {
    my $ts = sprintf('22/Jun/2026:12:30:%02d +0000', $i);
    print qq{198.51.100.42 - - [$ts] "GET /index.html HTTP/1.1" 200 5123 "-" "Mozilla/5.0"\n};
}
