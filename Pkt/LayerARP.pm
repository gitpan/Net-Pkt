package Net::Pkt::LayerARP;

# $Date: 2004/08/29 19:10:21 $
# $Revision: 1.21.2.1 $

# ARP: STD0037/RFC0826

use strict;
use warnings;
use Carp;

require Exporter;
require Net::Pkt::Layer3;
our @ISA = qw(Net::Pkt::Layer3 Exporter);
our @EXPORT_OK = qw(
   NETPKT_ARP_HTYPE_ETH
   NETPKT_ARP_PTYPE_IPv4
   NETPKT_ARP_HSIZE_ETH
   NETPKT_ARP_PSIZE_IPv4
   NETPKT_ARP_OPCODE_REQUEST
   NETPKT_ARP_OPCODE_REPLY
   NETPKT_ARP_ADDR_BROADCAST
);

use Socket;

use constant NETPKT_ARP_HTYPE_ETH      => 0x0001;
use constant NETPKT_ARP_PTYPE_IPv4     => 0x0800;
use constant NETPKT_ARP_HSIZE_ETH      => 0x06;
use constant NETPKT_ARP_PSIZE_IPv4     => 0x04;
use constant NETPKT_ARP_OPCODE_REQUEST => 0x0001;
use constant NETPKT_ARP_OPCODE_REPLY   => 0x0002;
use constant NETPKT_ARP_ADDR_BROADCAST => '00:00:00:00:00:00';

our @AccessorsScalar = qw(
   hType
   pType
   hSize
   pSize
   opCode
   src
   dst
   srcIp
   dstIp
   padding
);

sub new {
   my $self = shift->SUPER::new(
      hType   => NETPKT_ARP_HTYPE_ETH,
      pType   => NETPKT_ARP_PTYPE_IPv4,
      hSize   => NETPKT_ARP_HSIZE_ETH,
      pSize   => NETPKT_ARP_PSIZE_IPv4,
      opCode  => NETPKT_ARP_OPCODE_REQUEST,
      src     => Net::Pkt->autoMac,
      dst     => NETPKT_ARP_ADDR_BROADCAST,
      srcIp   => Net::Pkt->autoIp,
      dstIp   => "127.0.0.1",
      padding => "G" x 18, # to accomplish Ethernet frame size => no memleak ;)
      @_,
   );

   $self->src(lc $self->src) if $self->src;
   $self->dst(lc $self->dst) if $self->dst;

   # Some aliases
   *srcMac = \&src;
   *dstMac = \&dst;

   return $self;
}

sub pack {
   my $self = shift;

   (my $srcMac = $self->src) =~ s/://g;
   (my $dstMac = $self->dst) =~ s/://g;

   $self->raw(
      pack('nnUUnH12a4H12a4 a*',
         $self->hType,
         $self->pType,
         $self->hSize,
         $self->pSize,
         $self->opCode,
         $srcMac,
         inet_aton($self->srcIp),
         $dstMac,
         inet_aton($self->dstIp),
         $self->padding,
      ),
   );

   $self->rawLength(length $self->raw);
}

sub unpack {
   my $self = shift;

   my ($hType, $pType, $hSize, $pSize, $opCode, $srcMac, $srcIp, $dstMac,
       $dstIp, $padding) = unpack('nnUUnH12a4H12a4 a*', $self->raw);

   $self->hType($hType);
   $self->pType($pType);
   $self->hSize($hSize);
   $self->pSize($pSize);
   $self->opCode($opCode);
   $self->src(Net::Pkt->convertMac($srcMac));
   $self->srcIp(inet_ntoa($srcIp));
   $self->dst(Net::Pkt->convertMac($dstMac));
   $self->dstIp(inet_ntoa($dstIp));
   $self->padding($padding);
}

sub recv {
   my $self = shift;

   my $src    = $self->src;
   my $srcIp  = $self->srcIp;
   my $dstIp  = $self->dstIp;
   my $opCode = $self->opCode;

   for ($Net::Pkt::Dump->frames) {
      if ($_->isFrameArp) {
         if ($opCode == NETPKT_ARP_OPCODE_REQUEST) {
            if ($_->l3->opCode == NETPKT_ARP_OPCODE_REPLY
            &&  $_->l3->dst    eq $src
            &&  $_->l3->srcIp  eq $dstIp
            &&  $_->l3->dstIp  eq $srcIp) {
               return $_;
            }
         }
      }
   }

   return undef;
}

sub encapsulate { Net::Pkt::Frame::NETPKT_LAYER_NONE() }

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $i = $self->is;
   printf
      "$l:+$i: hType:0x%.4x  hSize:0x%.2x  pType:0x%.4x  pSize:0x%.2x\n".
      "$l: $i: srcMac:%s => dstMac:%s\n".
      "$l: $i: srcIp:%s => dstIp:%s\n".
      "$l: $i: opCode:0x%.4x  padding:%s\n".
      "",
         $self->hType,  $self->hSize, $self->pType, $self->pSize,
         $self->src,    $self->dst,
         $self->srcIp,  $self->dstIp,
         $self->opCode, CORE::unpack('H*', $self->padding),
   ;
}

#
# Accessors
#

for my $a (@AccessorsScalar) {
   no strict 'refs';
   *$a = sub { shift->_AccessorScalar($a, @_) }
}

1;

__END__

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENCE

Copyright (c) 2004, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic licence.
See Copying file in the source distribution archive.

=head1 RELATED MODULES

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut
