package Net::Pkt::LayerUDP;

# $Date: 2004/08/29 19:10:21 $
# $Revision: 1.6.2.1 $

#
# RFC0768: http://www.rfc-editor.org/rfc/rfc768.txt
#                                   
#  0      7 8     15 16    23 24    31 
# +--------+--------+--------+--------+
# |          source address           |
# +--------+--------+--------+--------+
# |        destination address        |
# +--------+--------+--------+--------+
# |  zero  |protocol|   UDP length    |
# +--------+--------+--------+--------+
#
#  0      7 8     15 16    23 24    31  
# +--------+--------+--------+--------+ 
# |     Source      |   Destination   | 
# |      Port       |      Port       | 
# +--------+--------+--------+--------+ 
# |                 |                 | 
# |     Length      |    Checksum     | 
# +--------+--------+--------+--------+ 
# |                                     
# |          data octets ...            
# +---------------- ...                 
#

use strict;
use warnings;
use Carp;

require Exporter;
require Net::Pkt::Layer4;
our @ISA = qw(Net::Pkt::Layer4 Exporter);
our @EXPORT_OK = qw( 
   NETPKT_UDP_HDR_LEN
);

use Socket;

use constant NETPKT_UDP_HDR_LEN => 8;

our @AccessorsScalar = qw(
   src
   dst
   len
   checksum
   headerLength
   totalLength
);

sub new {
   my $self = shift->SUPER::new(
      src      => Net::Pkt->getRandomHighPort,
      dst      => 0,
      len      => 0,
      checksum => 0,
      @_,
   );

   # Compute helper lengths if packet is unpacked (and accessors are set up)
   unless ($self->raw) {
      $self->_computeHeaderLength;
   }

   return $self;
}

sub recv {
   my ($self, $l3) = @_;

   my $src   = $l3->src;
   my $dst   = $l3->dst;
   my $sport = $self->src;
   my $dport = $self->dst;
   
   for ($Net::Pkt::Dump->frames) {
      if ($_->isFrameUdp) {
         if ($_->l3->src eq $dst
         &&  $_->l3->dst eq $src
         &&  $_->l4->src == $dport
         &&  $_->l4->dst == $sport) {
            return $_;
         }
      }
   }

   return undef;
}

sub pack {
   my $self = shift;

   $self->raw(
      pack('nnnS',
         $self->src,
         $self->dst,
         $self->len,
         $self->checksum,
      ),
   );

   $self->raw($self->raw);
   $self->rawLength(length $self->raw);
}

sub unpack {
   my $self = shift;

   my ($src, $dst, $len, $checksum, $payload) = unpack('nnnS a*', $self->raw);

   $self->src($src);
   $self->dst($dst);
   $self->len($len);
   $self->checksum($checksum);
   $self->payload($payload);

   $self->_computeHeaderLength;
   $self->totalLength($self->len);
}

sub _computeHeaderLength { shift->headerLength(NETPKT_UDP_HDR_LEN) }

sub _computeTotalLength {
   my ($self, $l7) = @_;

   # Autocompute header length if not user specified
   return if $self->len;

   my $totalLength = NETPKT_UDP_HDR_LEN;
   $totalLength += $l7->dataLength if $l7;
   $self->len($totalLength);
}

sub computeLengths {
   my ($self, $l7) = @_[0, 4];
   $self->_computeHeaderLength;
   $self->_computeTotalLength($l7);
}

sub computeChecksums {
   my $self = shift;
   my ($l2, $l3, $l4, $l7) = @_;

   my $phpkt =
      CORE::pack('a4a4CCn nnnS',
         inet_aton($l3->src),
         inet_aton($l3->dst),
         0,
         $l3->protocol,
         $self->len,
         $self->src,
         $self->dst,
         $self->len,
         $self->checksum,
      );
   $phpkt .= CORE::pack('a*', $l7->data) if $l7;
   $self->checksum(Net::Pkt->inetChecksum($phpkt));
}

sub encapsulate {
   shift->payload
      ? Net::Pkt::Frame::NETPKT_LAYER_7()
      : Net::Pkt::Frame::NETPKT_LAYER_NONE();
}

sub print {
   my $self = shift;

   my $i = $self->is;
   my $l = $self->layer;
   printf
      "$l:+$i: checksum:0x%.4x  [%d => %d]\n".
      "$l: $i: size:%d  header:%d\n",
         $self->checksum,
         $self->src,
         $self->dst,
         $self->len,
         NETPKT_UDP_HDR_LEN,
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
