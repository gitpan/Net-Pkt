#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('s:m:d:i:', \%opts);

die "Usage: arp-request.pl [ -i DEV ] [ -s SRC_IP ] [ -m SRC_MAC ] -d DST_IP\n"
   unless $opts{d};

$Net::Pkt::Debug++;

$Net::Pkt::Dev = $opts{i};
$Net::Pkt::Ip = $opts{s};
$Net::Pkt::Mac = $opts{m};

use Net::Pkt::DescL2;
Net::Pkt::DescL2->new;

use Net::Pkt::Quick;
my $frame = Net::Pkt::Quick->arpRequest(
   whoHas    => $opts{d},
   tell      => $Net::Pkt::Ip,
   tellMac   => $Net::Pkt::Mac,
   toMac     => 'broadcast',
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
