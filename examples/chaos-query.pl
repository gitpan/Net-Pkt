#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('d:i:I:v', \%opts);

die "Usage: chaos-query.pl -i dstIp [ -I srcIp ] [ -d device ] [ -v ]\n"
   unless $opts{i};

$Net::Pkt::Debug = 3 if $opts{v};

$Net::Pkt::Dev = $opts{d};
$Net::Pkt::Ip  = $opts{I};

use Net::Pkt::DescL3;
Net::Pkt::DescL3->new(ipDst => $opts{i});

use Net::Pkt::Frame;
use Net::Pkt::LayerIPv4 qw(/NETPKT_*/);
my $l3 = Net::Pkt::LayerIPv4->new(
   protocol => NETPKT_IPv4_PROTOCOL_UDP,
   src      => $Net::Pkt::Ip,
   dst      => $opts{i},
);

my $l4 = Net::Pkt::LayerUDP->new(dst => 53);

my $l7 = Net::Pkt::Layer7->new(
   data => "\x33\xde\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65".
           "\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03",
);

my $frame = Net::Pkt::Frame->new(l3 => $l3, l4 => $l4, l7 => $l7);

use Net::Pkt::Dump;
my $dump = Net::Pkt::Dump->new(
   filter             => $frame->getFilter,
   unlinkAfterAnalyze => 1,
   callStart          => 1,
);

print "Request:\n";
$frame->ipPrint;
$frame->udpPrint;
$frame->l7Print;
$frame->send;

until ($Net::Pkt::Timeout) {
   if ($dump->next && $frame->recv) {
      print "\nReply:\n";
      $frame->reply->ipPrint;
      $frame->reply->udpPrint;
      $frame->reply->l7Print;
      last;
   }
}
