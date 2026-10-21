#!/usr/bin/env perl
#
# A nameserver for one purpose: it answers every A query with the address
# that stands in a file, and with a time to live of zero, so that a test can
# change the answer between two requests and nothing holds the old one.
#
# usage: ci/dns.pl <port> <file holding one dotted address>
#
# Only for the drivers under ci/.  It answers one question per packet, which
# is what a resolver asks, and nothing else.

use strict;
use warnings;
use IO::Socket::INET;

my ($port, $file) = @ARGV;
die "usage: dns.pl <port> <file>\n" unless defined $port && defined $file;

my $sock = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => $port,
    Proto     => 'udp',
) or die "dns.pl: cannot listen on 127.0.0.1:$port: $!\n";

$| = 1;
print "dns.pl: listening on 127.0.0.1:$port, answering from $file\n";

while (1) {
    my $query;
    my $peer = $sock->recv($query, 512);
    next unless defined $peer && defined $query && length($query) > 12;

    # The question ends at the root label, and the type and class follow it.
    my $end = 12;
    $end++ while $end < length($query) && substr($query, $end, 1) ne "\0";
    next if $end + 5 > length($query);

    my $question = substr($query, 12, $end - 12 + 5);
    my $id       = unpack('n', substr($query, 0, 2));
    my $qtype    = unpack('n', substr($query, $end + 1, 2));

    my $answer  = '';
    my $ancount = 0;

    if ($qtype == 1) {
        my $addr = '';
        if (open(my $fh, '<', $file)) {
            $addr = <$fh> // '';
            close($fh);
        }
        chomp $addr;
        my @octets = split(/\./, $addr);

        if (@octets == 4) {
            # 0xC00C points back at the name in the question
            $answer  = pack('n n n N n C4', 0xC00C, 1, 1, 0, 4, @octets);
            $ancount = 1;
        }
    }

    # QR, RD and RA set, no error: an empty answer is then "no such data",
    # which is what an AAAA question gets here.
    my $reply = pack('n n n n n n', $id, 0x8180, 1, $ancount, 0, 0)
              . $question . $answer;

    $sock->send($reply, 0, $peer);
}
