package Net::Pkt::LayerIPv4;

# $Date: 2004/08/29 19:10:21 $
# $Revision: 1.45.2.1 $

use strict;
use warnings;
use Carp;

require Exporter;
require Net::Pkt::Layer3;
our @ISA = qw(Net::Pkt::Layer3 Exporter);
our @EXPORT_OK = qw(
   NETPKT_IPv4_HDR_LEN
   NETPKT_IPv4_V4
   NETPKT_IPv4_TRANSPORT_TCP
   NETPKT_IPv4_TRANSPORT_UDP
   NETPKT_IPv4_MORE_FRAGMENT
   NETPKT_IPv4_DONT_FRAGMENT
   NETPKT_IPv4_RESERVED_FRAGMENT
);

use Socket;

use constant NETPKT_IPv4_HDR_LEN           => 20;
use constant NETPKT_IPv4_V4                => 4;
use constant NETPKT_IPv4_TRANSPORT_TCP     => 6;
use constant NETPKT_IPv4_TRANSPORT_UDP     => 17;
use constant NETPKT_IPv4_MORE_FRAGMENT     => 0x2000;
use constant NETPKT_IPv4_DONT_FRAGMENT     => 0x4000;
use constant NETPKT_IPv4_RESERVED_FRAGMENT => 0x8000;

BEGIN {
   my $osname = {
      freebsd => '_fixLenBsd',
      netbsd  => '_fixLenBsd',
   };

   *_fixLen = \&{$osname->{$^O} || '_fixLenOther'};

   # Some aliases
   *flags       = \&off;
   *totalLength = \&len;
}

sub _fixLenBsd   { pack('v', shift) }
sub _fixLenOther { pack('n', shift) }

our @AccessorsScalar = qw(
   id
   ttl
   src
   dst
   protocol
   checksum
   off
   ver
   tos
   len
   hlen
   options
   optionsLength
   headerLength
);
      
sub new {
   my $self = shift->SUPER::new(
      ver      => 4,
      tos      => 0,
      id       => Net::Pkt->getRandom16bitInt,
      len      => 0,
      hlen     => 0,
      off      => 0,
      ttl      => 128,
      protocol => NETPKT_IPv4_TRANSPORT_TCP,
      checksum => 0,
      src      => Net::Pkt->autoIp,
      dst      => "127.0.0.1",
      options  => "",
      @_,
   );

   # Compute helper lengths if packet is unpacked (and accessors are set up)
   unless ($self->raw) {
      # Autocompute header length if not user specified
      unless ($self->hlen) {
         my $hLen = NETPKT_IPv4_HDR_LEN;
         $hLen   += length ($self->options) if $self->options;
         $self->hlen($hLen / 4);
      }

      $self->_computeHeaderLength;
      $self->_computeOptionsLength;
   }

   return $self;
}

sub pack {
   my $self = shift;

   # Thank you Stephanie Wehner
   my $hlenVer  = ($self->hlen & 0x0f) | (($self->ver << 4) & 0xf0);
   my $offFlags = ($self->flags << 13) | (($self->off >> 3) & 0x1fff);

   $self->raw(
      pack('CCa*nnCCna4a4',
         $hlenVer,
         $self->tos,
         _fixLen($self->len),
         $self->id,
         $offFlags,
         $self->ttl,
         $self->protocol,
         $self->checksum,
         inet_aton($self->src),
         inet_aton($self->dst),
      ),
   );

   $self->raw($self->raw. pack('a*', $self->options)) if $self->options;
   $self->rawLength(length $self->raw);
}

sub unpack {
   my $self = shift;

   my ($verHlen, $tos, $len, $id, $off, $ttl, $proto, $cksum, $src, $dst,
       $payload) = unpack('CCnnnCCna4a4 a*', $self->raw);

   $self->ver(($verHlen & 0xf0) >> 4);
   $self->hlen($verHlen & 0x0f);
   $self->tos($tos);
   $self->len($len);
   $self->id($id);
   $self->off($off);
   $self->ttl($ttl);
   $self->protocol($proto);
   $self->checksum($cksum);
   $self->src(inet_ntoa($src));
   $self->dst(inet_ntoa($dst));
   $self->payload($payload);

   $self->_computeHeaderLength;
   $self->_computeOptionsLength;

   my ($options, $payload2) =
      unpack('a'. $self->optionsLength. 'a*', $self->payload);

   $self->options($options);
   $self->payload($payload2);
}

sub _computeHeaderLength {
   my $self = shift;
   $self->headerLength($self->hlen * 4);
}

sub _computeOptionsLength {
   my $self = shift;
   $self->optionsLength($self->headerLength - NETPKT_IPv4_HDR_LEN);
}

sub _computeTotalLength {
   my $self = shift;
   my ($l4, $l7) = @_;

   # Do not compute if user specified
   return if $self->len;

   my $total = $self->headerLength;
   $total += $l4->headerLength;
   $total += $l7->dataLength if $l7; # Since L7 is optional
   $self->len($total);
}

sub computeLengths {
   my $self = shift;
   my ($l2, $l3, $l4, $l7) = @_;

   carp("@{[(caller(0))[3]]}: you must pass in a Layer 4 object")
      unless $l4;

   $l4->computeLengths(undef, undef, undef, $l7);
   $l7->computeLengths(undef, undef, undef, undef) if $l7;

   $self->_computeHeaderLength;
   $self->_computeTotalLength($l4, $l7);
   $self->_computeOptionsLength;
}

sub encapsulate {
   my $types = {
      NETPKT_IPv4_TRANSPORT_TCP() => Net::Pkt::Frame::NETPKT_LAYER_TCP(),
      NETPKT_IPv4_TRANSPORT_UDP() => Net::Pkt::Frame::NETPKT_LAYER_UDP(),
   };

   $types->{shift->protocol} || Net::Pkt::Frame::NETPKT_LAYER_UNKNOWN();
}

sub print {
   my $self = shift;

   my $i = $self->is;
   my $l = $self->layer;
   printf
      "$l:+$i: ver:%d  id:%.4d  ttl:%d  [%s => %s]\n".
      "$l: $i: tos:0x%.2x  flags:0x%.4x  checksum:0x%.4x  protocol:0x%.2x\n".
      "$l: $i: size:%d  header:%d  options:%d  payload:%d\n",
         $self->ver,
         $self->id,
         $self->ttl,
         $self->src,
         $self->dst,
         $self->tos,
         $self->off,
         $self->checksum,
         $self->protocol,
         $self->len,
         $self->headerLength,
         $self->optionsLength,
         $self->len - $self->headerLength,
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

sub _haveFlag  { shift->off & shift() ? 1 : 0                    }
sub haveFlagDf { shift->_haveFlag(NETPKT_IPv4_DONT_FRAGMENT)     }
sub haveFlagMf { shift->_haveFlag(NETPKT_IPv4_MORE_FRAGMENT)     }
sub haveFlagRf { shift->_haveFlag(NETPKT_IPv4_RESERVED_FRAGMENT) }

sub isV4 { shift->ver == NETPKT_IPv4_V4 ? 1 : 0 }

sub isTransportTcp { shift->protocol == NETPKT_IPv4_TRANSPORT_TCP ? 1 : 0 }
sub isTransportUdp { shift->protocol == NETPKT_IPv4_TRANSPORT_UDP ? 1 : 0 }

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
