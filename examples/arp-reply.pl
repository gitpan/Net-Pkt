#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('m:M:i:a:d:', \%opts);

die "Usage: arp-reply.pl  -i dstIp -a isAtMac [ -M srcMac ] [ -m dstMac ] ".
    "(or will broadcast) [ -d device ]\n"
   unless $opts{i} && $opts{a};

$Net::Pkt::Debug++;

$Net::Pkt::Dev = $opts{d};
$Net::Pkt::Mac = $opts{M};

use Net::Pkt::DescL2;
Net::Pkt::DescL2->new;

use Net::Pkt::Quick;
my $frame = Net::Pkt::Quick->arpReply(
   srcMac => $Net::Pkt::Mac,
   ip     => $opts{i},
   isAt   => $opts{a},
   toMac  => $opts{m} ? $opts{m} : 'broadcast',
);

print "Sending:\n";
$frame->ethPrint;
$frame->arpPrint;

$frame->send;
