#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:I:d:v', \%opts);

die "Usage: icmp-timestamp.pl -i dstIp [ -I srcIp ] [ -d device ]\n"
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
my $timestamp = Net::Pkt::LayerICMPv4->new(
   type               => NETPKT_ICMPv4_TYPE_TIMESTAMP_REQUEST,
   originateTimestamp => 0xffffffff,
   receiveTimestamp   => 0,
   transmitTimestamp  => 0,
   data               => "test",
);

my $frame = Net::Pkt::Frame->new(l3 => $ip, l4 => $timestamp);

use Net::Pkt::Dump;
my $dump = Net::Pkt::Dump->new(
   filter             => $frame->getFilter,
   unlinkAfterAnalyze => 1,
);

$dump->start;

$frame->send;

$dump->stop;

$dump->analyze;
if (my $reply = $frame->recv) {
   $reply->l4->print;
}
