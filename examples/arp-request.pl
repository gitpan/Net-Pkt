#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('i:I:M:d:vt', \%opts);

die "Usage: arp-request.pl -i dstIp [ -I srcIp ] [ -M srcMac ] [ -d device ] ".
    "[ -v ] [ -t timeout ]\n"
   unless $opts{i};

$Net::Pkt::Debug = 3 if $opts{v};

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
   callStart          => 1,
   timeoutOnNext      => $opts{t} ? $opts{t} : 3,
);

print "Request:\n";
$frame->ethPrint;
$frame->arpPrint;
$frame->send;

until ($Net::Pkt::Timeout) {
   if ($dump->next && $frame->recv) {
      print "\nReply:\n";
      $frame->reply->ethPrint;
      $frame->reply->arpPrint;
      print "\n", $frame->reply->arpSrcIp, " is-at ", $frame->reply->arpSrc,
            "\n";
      last;
   }
}
