#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('d:I:M:n:vt:kr:', \%opts);

die "Usage: arp-scan.pl [ -d device ] [ -I srcIp ] [ -M srcMac ] [ -v ] ".
    "[ -t timeout ] [ -k ] [ -r number ] -n C.SUB.NET\n"
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
   filter    => "arp",
   callStart => 1,
);

my $times = $opts{r} ? $opts{r} : 3;
for (1..$times) {
   do { $_->send unless $_->reply } for @frames;

   sleep($opts{t} ? $opts{t} : 3);

   $dump->analyze;

   for (@frames) {
      if ($_->recv) {
         print "Reply:\n";
         $_->reply->ethPrint;
         $_->reply->arpPrint;
      }
   }
}

unlink $dump->file unless $opts{k};

for (@frames) {
   print $_->reply->arpSrcIp, " => ", $_->reply->arpSrc, "\n" if $_->reply;
}
