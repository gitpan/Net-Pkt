#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:I:p:d:', \%opts);

die "Usage: send-syn.pl -i dstIp -p dstPort [ -I srcIp ] [ -d device ]\n"
   unless $opts{i} && $opts{p};

$Net::Pkt::Debug = 3;

# Overwrite autochosen one
$Net::Pkt::Dev = $opts{d};
$Net::Pkt::Ip  = $opts{I};

use Net::Pkt::DescL3;
my $desc = Net::Pkt::DescL3->new(ipDst => $opts{i});

use Net::Pkt::Quick;
my $frame = Net::Pkt::Quick->tcpSyn(
   ipSrc   => $Net::Pkt::Ip,
   ipDst   => $opts{i},
   dstPort => $opts{p},
);

use Net::Pkt::Dump;
my $dump = Net::Pkt::Dump->new(
   filter             => $frame->getFilter,
   unlinkAfterAnalyze => 1,
);

$dump->start;

print "Request:\n";
$frame->ipPrint;
$frame->tcpPrint;
$frame->send;

$dump->stop;

$dump->analyze;
if (my $reply = $frame->recv) {
   print "\nReply:\n";
   $reply->ipPrint;
   $reply->tcpPrint;
}
