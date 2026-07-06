#!/usr/bin/env perl
# Generates examples/logs/spike.log: steady RFC3164 baseline + a sharp burst.
# Baseline ~2 events / 60s bucket for 20 min, then a 60s spike of 60 events.
use strict; use warnings;
my $base_epoch = 1750593600;  # fixed reference (2025-06-22 12:00:00 UTC-ish)
sub emit {
    my ($epoch, $msg) = @_;
    my @lt = gmtime($epoch);
    my @mon = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    printf "%s %2d %02d:%02d:%02d host01 app[%d]: %s\n",
        $mon[$lt[4]], $lt[3], $lt[2], $lt[1], $lt[0], 1000, $msg;
}
# baseline: 2 events every 60s for 20 buckets
for my $b (0..19) {
    for my $k (0..1) {
        emit($base_epoch + $b*60 + $k*20, "routine health check ok id=$b$k");
    }
}
# spike: 60 events in one 60s window (bucket 25)
for my $k (0..59) {
    emit($base_epoch + 25*60 + $k, "connection reset by peer id=$k");
}
