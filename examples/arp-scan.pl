#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('d:I:M:n:vt:', \%opts);

die "Usage: arp-scan.pl [ -d device ] [ -I srcIp ] [ -M srcMac ] [ -v ] ".
    "[ -t timeout ] -n C.SUB.NET\n"
   unless $opts{n};

die "Invalid C class: $opts{n}\n" unless $opts{n} =~ /^\d+\.\d+\.\d+/;
$opts{n} =~ s/^(\d+\.\d+\.\d+).*$/$1/;

$Net::Pkt::Debug = 3 if $opts{v};

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
   callStart          => 1,
   timeoutOnNext      => $opts{t} ? $opts{t} : 5,
);

$_->send for @frames;

until ($Net::Pkt::Timeout) {
   # If a new packet has been received, and it is an ARP reply, we try to see 
   # if it is a response to one of our requests
   if ($dump->next && $dump->nextFrame->arpIsReply) {
      for (@frames) {
         next if $_->reply; # Already received the reply, so skip
         if (my $reply = $_->recv) {
            print "Reply:\n";
            $reply->ethPrint;
            $reply->arpPrint;
         }
      }
   }
}

for (@frames) {
   print $_->reply->arpSrcIp, " => ", $_->reply->arpSrc, "\n" if $_->reply;
}
