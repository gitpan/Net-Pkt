package Net::Pkt;

# $Date: 2004/09/26 11:36:32 $
# $Revision: 1.39.2.9 $

require v5.6.1;

use strict;
use warnings;
use Carp;

require Exporter;
require DynaLoader;
use AutoLoader;

our @ISA = qw(Exporter DynaLoader);

our $VERSION = '0.24';

use Net::Pcap;
use IO::Socket::INET;
use IO::Interface;

our $_UdpSocket;

BEGIN {
   die("Must be EUID 0 to use Net::Pkt") if $>;

   die("Big endian architectures not supported yet")
      if unpack("h*", pack("s", 1)) =~ /01/;

   $_UdpSocket = IO::Socket::INET->new(Proto => 'udp')
      or die("@{[(caller(0))[3]]}: IO::Socket::INET->new: $!\n");

}

CHECK {
   __PACKAGE__->autoDev;
   __PACKAGE__->autoIp;
   __PACKAGE__->autoMac;
}

sub AUTOLOAD {
   # This AUTOLOAD is used to 'autoload' constants from the constant()
   # XS function.  If a constant is not found then control is passed
   # to the AUTOLOAD in AutoLoader.

   my $constname;
   our $AUTOLOAD;
   ($constname = $AUTOLOAD) =~ s/.*:://;
   croak "& not defined" if $constname eq 'constant';
   my $val = constant($constname, @_ ? $_[0] : 0);
   if ($! != 0) {
      if ($! =~ /Invalid/ || $!{EINVAL}) {
         $AutoLoader::AUTOLOAD = $AUTOLOAD;
         goto &AutoLoader::AUTOLOAD;
      }
      else {
         croak "Your vendor has not defined Net::Pkt macro $constname";
      }
   }
   {
      no strict 'refs';
      # Fixed between 5.005_53 and 5.005_61
      if ($] >= 5.00561) {
         *$AUTOLOAD = sub () { $val };
      }
      else {
         *$AUTOLOAD = sub { $val };
      }
   }
   goto &$AUTOLOAD;
}

bootstrap Net::Pkt $VERSION;

our $Err;
our $Debug;

our $Dev;
our $Ip;
our $Mac;
our $Desc;
our $Dump;
our $Promisc = 0;
our $Timeout = 0;

sub new {
   my $invocant = shift;
   my $class = ref($invocant) || $invocant;

   $class->checkParams({ @_ }, [ $class->getAccessors ])
      or croak($Err);

   return bless({ @_ }, $class);
}

sub autoDev {
   return $Dev if $Dev;

   my $err;
   $Dev = Net::Pcap::lookupdev(\$err);
   if (defined $err) {
      croak("@{[(caller(0))[3]]}: Net::Pcap::lookupdev: $err ; ".
            "unable to autochoose Dev");
   }

   return $Dev;
}

sub autoIp {
   return $Ip if $Ip;

   $Ip = $_UdpSocket->if_addr($Dev)
      or croak("@{[(caller(0))[3]]}: unable to autochoose IP from $Dev");

   return $Ip;
}

sub _ifconfigGetMac {
   return undef unless $Dev =~ /^[a-z]+[0-9]+$/;
   my $buf = `/sbin/ifconfig $Dev 2> /dev/null`;
   $buf =~ /([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})/i;
   $1 ? return lc($1)
      : return 'ff:ff:ff:ff:ff:ff';
}

sub autoMac {
   return $Mac if $Mac;

   # On some systems, if_hwaddr simply does not work, we try to get MAC from 
   # `ifconfig $Dev`
   unless ($Mac = $_UdpSocket->if_hwaddr($Dev) || _ifconfigGetMac()) {
      croak("@{[(caller(0))[3]]}: unable to autochoose Mac from $Dev");
   }

   return $Mac;
}

sub getRandomHighPort {
   my $highPort = int rand 0xffff;
   $highPort += 1024 if $highPort < 1025;
   return $highPort;
}

sub getRandom32bitsInt { return int rand 0xffffffff }
sub getRandom16bitsInt { return int rand 0xffff }

sub convertMac {
   shift;
   my $mac = shift;
   $mac =~ s/(..)/$1:/g;
   $mac =~ s/:$//;
   return lc $mac;
}

sub inetChecksum {
   shift;
   my $phpkt = shift;

   $phpkt      .= "\x00" if length($phpkt) % 2;
   my $len      = length $phpkt;
   my $nshort   = $len / 2;
   my $checksum = 0;
   $checksum   += $_ for unpack("S$nshort", $phpkt);
   $checksum   += unpack('C', substr($phpkt, $len - 1, 1)) if $len % 2;
   $checksum    = ($checksum >> 16) + ($checksum & 0xffff);

   return ~(($checksum >> 16) + $checksum) & 0xffff;
}

sub debugPrint {
   return unless $Net::Pkt::Debug;

   my ($invocant, $msg) = @_;
   (my $pm = ref($invocant) || $invocant) =~ s/^Net::Pkt:://;
   $msg =~ s/^/DEBUG: $pm: /gm;
   print STDERR "$msg\n";
}

sub checkParams {
   my ($invocant, $userParams, $accessors) = @_;
   my $class = ref($invocant) || $invocant;

   for my $u (keys %$userParams) {
      my $valid;
      my $defined;
      for (@$accessors) {
         $u eq $_ ? $valid++ : next;
         do { $defined++; last; } if defined $userParams->{$u};
      }
      unless ($valid) {
         $Err = "$class: invalid parameter: `$u'";
         return undef;
      }
      unless ($defined) {
         $Err = "$class: parameter is undef: `$u'";
         return undef;
      }
   }

   return 1;
}

sub getAccessors {
   my $self = shift;

   no strict 'refs';

   my @accessors;
   @accessors = ( @{$self. '::AccessorsScalar'} )
      if @{$self. '::AccessorsScalar'};
   @accessors = ( @accessors, @{$self. '::AccessorsArray'})
      if @{$self. '::AccessorsArray'};

   return @accessors;
}

sub _AccessorScalar {
   my ($self, $sca) = (shift, shift);
   @_ ? $self->{$sca} = shift
      : $self->{$sca};
}

sub _AccessorArray {
   my ($self, $ary) = (shift, shift);
   @_ ? $self->{$ary} = shift
      : @{$self->{$ary}};
}

1;

__END__

=head1 NAME

Net::Pkt - a unified framework to read and write packets over networks from layer 2 to layer 7

=head1 CLASS HIERARCHY

  Net::Pkt
     |
     +---Net::Pkt::Dump
     |
     +---Net::Pkt::Desc
     |      |
     |      +---Net::Pkt::DescL2
     |      |
     |      +---Net::Pkt::DescL3
     |      |
     |      +---Net::Pkt::DescL4
     |      |
     |      +---Net::Pkt::DescL7
     |
     +---Net::Pkt::Frame
            |
            +---Net::Pkt::Layer
                   |
                   +---Net::Pkt::Layer2
                   |      |
                   |      +---Net::Pkt::LayerETH
                   |
                   +---Net::Pkt::Layer3
                   |      |
                   |      +---Net::Pkt::LayerARP
                   |      |
                   |      +---Net::Pkt::LayerIPv4
                   |
                   +---Net::Pkt::Layer4
                   |      |
                   |      +---Net::Pkt::LayerTCP
                   |      |
                   |      +---Net::Pkt::LayerUDP
                   |      |
                   |      +---Net::Pkt::LayerICMPv4
                   |
                   +---Net::Pkt::Layer7
   
  Net::Pkt::Quick

=head1 DESCRIPTION

This module is a unified framework to craft, send and receive packets at layers 2, 3, 4 and 7 (but 4 and 7 are just here for completeness, they have not been thoroughly tested. And you should use IO::Socket for layer 7, anyway).

Basically, you forge each layer of a frame (Net::Pkt::LayerIPv4 for layer 3, Net::Pkt::LayerTCP for layer 4 ; for example), and pack all of this into a Net::Pkt::Frame object. Then, you can write it to the network, and use Net::Pkt::Dump to receive responses.

=head1 GETTING STARED

When you use Net::Pkt for the first time in a program, three package variables are automatically set in Net::Pkt module: $Net::Pkt::Dev, $Net::Pkt::Ip, and $Net::Pkt::Mac. They are taken from the default interface on your machine, the one taken by tcpdump when not user specified. I recommand you to set the package variable $Net::Pkt::Debug to 3 when you are a beginner of this module.

Then, you must set a descriptor that will be used to send and receive packets. We will take as example a program that creates a TCP SYN packet and send it to a target host (10.0.0.1) and port (22):

   $Net::Pkt::Debug = 3;

   use Net::Pkt::DescL3;
   my $desc = Net::Pkt::DescL3->new(ipDst => "10.0.0.1");

When you use the new method with Net::Pkt::DescL3 class, the package variable $Net::Pkt::Desc is automatically set to use this instantiated object. We have used a Net::Pkt::DescL3 here, since we want to craft from the layer 3 (that is, from IP layer). See Net::Pkt::DescL3 for more.

Now that you have your descriptor ready, we can build the frame. So, we will build IP layer and TCP layer like this:

   use Net::Pkt::Frame;
   my $ip = Net::Pkt::LayerIPv4->new(
      dst => $desc->ipDst,
   );
   my $tcp = Net::Pkt::LayerTCP->new(
      dst => 22,
   );

You do not need to set the source IP, since it will be taken from the package variable $Net::Pkt::Ip. Also, reasonable defaults are set for other fields in those two layers. See Net::Pkt::LayerIPv4 and Net::Pkt::LayerTCP for more.

You have your layers 3 and 4, you can pack all into a frame:

   my $frame = Net::Pkt::Frame->new(l3 => $ip, l4 => $tcp);

Before sending this frame over the network, you should set a Net::Pkt::Dump instance object, that will be used to receive the response. When the new method is called, the package variable $Net::Pkt::Dump will be set.

   use Net::Pkt::Dump;
   my $dump = Net::Pkt::Dump->new(
      filter => $frame->getFilter,
      unlinkAfterAnalyze => 1,
   );
   $dump->start; # This forks a tcpdump process, with a reasonable filter 
                 # built using the created frame

The unlinkAfterAnalyze parameter is used to remove the temporary file created after calling the start method. If you want to keep the file for further analysis, you can remove this parameter. See Net::Pkt::Dump for more.

Finally:

   $frame->send;

   $dump->stop;    # Stops tcpdump process
   $dump->analyze; # Analyze what have been captured by tcpdump, and 
                   # unpack all frames into Net::Pkt::Frame format

   my $reply = $frame->recv; # Get the Net::Pkt::Frame corresponding to 
                             # the Net::Pkt::Frame request from captured 
                             # frames stored in $Net::Pkt::Dump->frames

   # Print response content, if any
   if ($reply) {
      $reply->ipPrint;
      $reply->tcpPrint;
   }

For more examples, see the examples directory in the source tarball.

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=head1 RELATED MODULES  

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut
