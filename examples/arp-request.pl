#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:I:M:d:', \%opts);

die "Usage: arp-request.pl -i dstIp [ -I srcIp ] [ -M srcMac ] [ -d device ]\n"
   unless $opts{i};

$Net::Pkt::Debug++;

$Net::Pkt::Dev = $opts{d};
$Net::Pkt::Ip  = $opts{I};
$Net::Pkt::Mac = $opts{M};

use Net::Pkt::DescL2;
Net::Pkt::DescL2->new;

use Net::Pkt::Quick;
my $frame = Net::Pkt::Quick->arpRequest(
   whoHas  => $opts{i},
   tell    => $Net::Pkt::Ip,
   tellMac => $Net::Pkt::Mac,
   toMac   => 'broadcast',
);

use Net::Pkt::Dump;
my $dump = Net::Pkt::Dump->new(
   filter             => $frame->getFilter,
   unlinkAfterAnalyze => 1,
);

$dump->start;

print "Request:\n";
$frame->ethPrint;
$frame->arpPrint;
$frame->send;

$dump->stop;

$dump->analyze;
if (my $reply = $frame->recv) {
   print "\nReply:\n";
   $reply->ethPrint;
   $reply->arpPrint;
   print "\n", $reply->arpSrcIp, " is-at ", $reply->arpSrc, "\n";
}
