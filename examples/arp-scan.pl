#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('d:I:M:n:', \%opts);

die "Usage: arp-scan.pl [ -d device ] [ -I srcIp ] [ -M srcMac ] -n C.SUB.NET\n"
   unless $opts{n};

die "Invalid C class: $opts{n}\n" unless $opts{n} =~ /^\d+\.\d+\.\d+/;
$opts{n} =~ s/^(\d+\.\d+\.\d+).*$/$1/;

$Net::Pkt::Debug++;

$Net::Pkt::Dev = $opts{d};
$Net::Pkt::Ip  = $opts{I};
$Net::Pkt::Mac = $opts{M};

use Net::Pkt::DescL2;
Net::Pkt::DescL2->new;

use Net::Pkt::Quick;

my @frames;
for (1..254) {
   my $frame = Net::Pkt::Quick->arpRequest(
      whoHas  => "$opts{n}.$_",
      tell    => $Net::Pkt::Ip,
      tellMac => $Net::Pkt::Mac,
      toMac   => 'broadcast',
   );
   push @frames, $frame;
}

use Net::Pkt::Dump;
my $dump = Net::Pkt::Dump->new(
   filter             => "arp",
   unlinkAfterAnalyze => 1,
);

$dump->start;

$frames[$_ - 1]->send for 1..254;

$dump->stop;

$dump->analyze;
my @replies;
for (1..254) {
   my $reply = $frames[$_ - 1]->recv;
   next unless $reply;
   print "Reply:\n";
   push @replies, $reply;
   $reply->ethPrint;
   $reply->arpPrint;
}

print $_->arpSrcIp, " => ", $_->arpSrc, "\n" for @replies;
