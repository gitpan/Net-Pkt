package Net::Pkt::LayerETH;

# $Date: 2004/09/02 16:21:10 $
# $Revision: 1.15.2.3 $

use strict;
use warnings;
use Carp;

require Exporter;
require Net::Pkt::Layer2;
our @ISA = qw(Net::Pkt::Layer2 Exporter);
our @EXPORT_OK = qw(
   NETPKT_ETH_ADDR_BROADCAST
   NETPKT_ETH_TYPE_IPv4
   NETPKT_ETH_TYPE_ARP
);

use constant NETPKT_ETH_ADDR_BROADCAST => 'ff:ff:ff:ff:ff:ff';
use constant NETPKT_ETH_TYPE_IPv4      => 0x0800;
use constant NETPKT_ETH_TYPE_ARP       => 0x0806;

our @AccessorsScalar = qw(
   src
   dst
   type
);

sub new {
   my $self = shift->SUPER::new(
      src  => NETPKT_ETH_ADDR_BROADCAST,
      dst  => NETPKT_ETH_ADDR_BROADCAST,
      type => NETPKT_ETH_TYPE_IPv4,
      @_,
   );

   $self->src(lc $self->src) if $self->src;
   $self->dst(lc $self->dst) if $self->dst;

   return $self;
}

sub pack {
   my $self = shift;

   (my $dst = $self->dst) =~ s/://g;
   (my $src = $self->src) =~ s/://g;

   $self->raw(pack('H12H12n', $dst, $src, $self->type));
   $self->rawLength(length $self->raw);
}

sub unpack {
   my $self = shift;

   my ($dst, $src, $type, $payload) = unpack('H12H12n a*', $self->raw);

   $self->dst(Net::Pkt->convertMac($dst));
   $self->src(Net::Pkt->convertMac($src));

   $self->type($type);
   $self->payload($payload);
}

sub encapsulate {
   my $types = {
      NETPKT_ETH_TYPE_IPv4() => Net::Pkt::Frame::NETPKT_LAYER_IPv4(),
      NETPKT_ETH_TYPE_ARP()  => Net::Pkt::Frame::NETPKT_LAYER_ARP(),
   };

   $types->{shift->type} || Net::Pkt::Frame::NETPKT_LAYER_UNKNOWN();
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $i = $self->is;
   printf
      "$l:+$i: type:0x%04x  [%s => %s]\n",
         $self->type, $self->src, $self->dst,
   ;
}

#
# Accessors
#

for my $a (@AccessorsScalar) {
   no strict 'refs';
   *$a = sub { shift->_AccessorScalar($a, @_) }
}

#
# Helpers
#

sub _isType    { shift->type == shift                 }
sub isTypeIpv4 { shift->_isType(NETPKT_ETH_TYPE_IPv4) }
sub isTypeArp  { shift->_isType(NETPKT_ETH_TYPE_ARP)  }

1;

__END__

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=head1 RELATED MODULES

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut
