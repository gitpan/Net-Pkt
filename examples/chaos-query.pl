#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:s:d:', \%opts);

die "Usage: chaos-query.pl [ -i DEV ] [ -s SRC_IP ] -d DST_IP\n"
   unless $opts{d};

$Net::Pkt::Debug++;

# Overwrite autochosen defaults
$Net::Pkt::Dev = $opts{i};
$Net::Pkt::Ip = $opts{s};

use Net::Pkt::DescL3;
Net::Pkt::DescL3->new(ipDst => $opts{d});

use Net::Pkt::Frame;
use Net::Pkt::LayerIPv4 qw(/NETPKT_*/);
my $l3 = Net::Pkt::LayerIPv4->new(
   protocol => NETPKT_IPv4_TRANSPORT_UDP,
   src => $Net::Pkt::Ip,
   dst => $opts{d},
);

my $l4 = Net::Pkt::LayerUDP->new(dst => 53);

my $l7 = Net::Pkt::Layer7->new(
   data => "\x33\xde\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03",
);

my $frame = Net::Pkt::Frame->new(l3 => $l3, l4 => $l4, l7 => $l7);

use Net::Pkt::Dump;
my $dump = Net::Pkt::Dump->new(
   filter => $frame->getFilter,
   unlinkAfterAnalyze => 1,
);

$dump->start;

print "Request:\n";
$frame->ipPrint;
$frame->udpPrint;
$frame->l7Print;
$frame->send;

$dump->stop;

$dump->analyze;
if (my $reply = $frame->recv) {
   print "\nReply:\n";
   $reply->ipPrint;
   $reply->udpPrint;
   $reply->l7Print;
}
