#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:I:p:d:v', \%opts);

die "Usage: send-syn.pl -i dstIp -p dstPort [ -I srcIp ] [ -d device ] ".
    "[ -v ]\n"
   unless $opts{i} && $opts{p};

$Net::Pkt::Debug = 3 if $opts{v};

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
   callStart          => 1,
);

print "Request:\n";
$frame->ipPrint;
$frame->tcpPrint;
$frame->send;

until ($Net::Pkt::Timeout) {
   if ($dump->next && $frame->recv) {
      print "\nReply:\n";
      $frame->reply->ipPrint;
      $frame->reply->tcpPrint;
      last;
   }
}
