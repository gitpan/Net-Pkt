#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('m:a:d:i:t:', \%opts);

die "Usage: arp-reply.pl [ -i DEV ] [ -m ETH_SRC_MAC ] -t IP ".
    "-a IS_AT_MAC [ -d DST_MAC ] (or will broadcast)\n"
   unless $opts{t} && $opts{a};

$Net::Pkt::Debug++;

$Net::Pkt::Dev = $opts{i};
$Net::Pkt::Mac = $opts{m};

use Net::Pkt::DescL2;
Net::Pkt::DescL2->new;

use Net::Pkt::Quick;
my $frame = Net::Pkt::Quick->arpReply(
   srcMac => $Net::Pkt::Mac,
   ip     => $opts{t},
   isAt   => $opts{a},
   toMac  => $opts{d} ? $opts{d} : 'broadcast',
);

print "Sending:\n";
$frame->ethPrint;
$frame->arpPrint;

$frame->send;
