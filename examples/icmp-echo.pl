#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:I:d:v', \%opts);

die "Usage: icmp-echo.pl -i dstIp [ -I srcIp ] [ -d device ] [ -v ]\n"
   unless $opts{i};

$Net::Pkt::Debug = 3 if $opts{v};

$Net::Pkt::Dev = $opts{d};
$Net::Pkt::Ip  = $opts{I};

use Net::Pkt::DescL3;
Net::Pkt::DescL3->new(ipDst => $opts{i});

use Net::Pkt::Frame;

use Net::Pkt::LayerIPv4 qw(/NETPKT_*/);
my $ip = Net::Pkt::LayerIPv4->new(
   protocol => NETPKT_IPv4_PROTOCOL_ICMPv4,
   dst      => $opts{i},
);

use Net::Pkt::LayerICMPv4 qw(/NETPKT_*/);
my $echo = Net::Pkt::LayerICMPv4->new(
   type => NETPKT_ICMPv4_TYPE_ECHO_REQUEST,
   data => "test",
);

my $frame = Net::Pkt::Frame->new(l3 => $ip, l4 => $echo);

use Net::Pkt::Dump;
my $dump = Net::Pkt::Dump->new(
   filter             => $frame->getFilter,
   unlinkAfterAnalyze => 1,
   callStart          => 1,
);

$frame->send;

until ($Net::Pkt::Timeout) {
   if ($dump->next && $frame->recv) {
      print "Reply:\n";
      $frame->reply->icmpPrint;
      last;
   }
}
