#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:s:d:p:', \%opts);

die "Usage: send-syn.pl [-i DEV ] [ -s SRC_IP ] -d DST_IP -p DST_PORT\n"
   unless $opts{d} && $opts{p};

#$Net::Pkt::Debug++;
$Net::Pkt::Debug = 3;

# Overwrite autochosen one
$Net::Pkt::Dev = $opts{i};
$Net::Pkt::Ip = $opts{s};

use Net::Pkt::DescL3;
my $desc = Net::Pkt::DescL3->new(ipDst => $opts{d});

use Net::Pkt::Quick;
my $frame = Net::Pkt::Quick->tcpSyn(
   ipSrc => $Net::Pkt::Ip,
   ipDst => $opts{d},
   dstPort => $opts{p},
);

use Net::Pkt::Dump;
my $dump = Net::Pkt::Dump->new(
   filter => $frame->getFilter,
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
