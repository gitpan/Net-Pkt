package Net::Pkt::LayerTCP;

# $Date: 2004/08/29 19:10:21 $
# $Revision: 1.46.2.1 $

#
# RFC0793: http://www.rfc-editor.org/rfc/rfc793.txt
#
# +--------+--------+--------+--------+
# |           Source Address          |
# +--------+--------+--------+--------+
# |         Destination Address       |
# +--------+--------+--------+--------+
# |  zero  |  PTCL  |    TCP Length   |
# +--------+--------+--------+--------+
#
#  0                   1                   2                   3   
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source Port          |       Destination Port        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        Sequence Number                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Acknowledgment Number                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Data |           |U|A|P|R|S|F|                               |
# | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
# |       |           |G|K|H|T|N|N|                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Checksum            |         Urgent Pointer        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Options                    |    Padding    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             data                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#

use strict;
use warnings;
use Carp;

require Exporter;
require Net::Pkt::Layer4;
our @ISA = qw(Net::Pkt::Layer4 Exporter);
our @EXPORT_OK = qw( 
   NETPKT_TCP_HDR_LEN
   NETPKT_TCP_FLAG_FIN
   NETPKT_TCP_FLAG_SYN
   NETPKT_TCP_FLAG_RST
   NETPKT_TCP_FLAG_PSH
   NETPKT_TCP_FLAG_ACK
   NETPKT_TCP_FLAG_URG
   NETPKT_TCP_FLAG_ECE
   NETPKT_TCP_FLAG_CWR
);

use Socket;

use constant NETPKT_TCP_HDR_LEN  => 20;
use constant NETPKT_TCP_FLAG_FIN => 0x01;
use constant NETPKT_TCP_FLAG_SYN => 0x02;
use constant NETPKT_TCP_FLAG_RST => 0x04;
use constant NETPKT_TCP_FLAG_PSH => 0x08;
use constant NETPKT_TCP_FLAG_ACK => 0x10;
use constant NETPKT_TCP_FLAG_URG => 0x20;
use constant NETPKT_TCP_FLAG_ECE => 0x40;
use constant NETPKT_TCP_FLAG_CWR => 0x80;

our @AccessorsScalar = qw(
   src
   dst
   flags
   win
   seq
   ack
   off
   x2
   checksum
   urp
   options
   optionsLength
   headerLength
);

sub new {
   my $self = shift->SUPER::new(
      src      => Net::Pkt->getRandomHighPort,
      dst      => 0,
      seq      => Net::Pkt->getRandom32bitInt,
      ack      => 0,
      x2       => 0,
      off      => 0,
      flags    => NETPKT_TCP_FLAG_SYN,
      win      => 0xffff,
      checksum => 0,
      urp      => 0,
      options  => "",
      @_,
   );

   # Compute helper lengths if packet is unpacked (and accessors are set up)
   unless ($self->raw) {
      # Autocompute header length if not user specified
      unless ($self->off) {
         my $hLen = NETPKT_TCP_HDR_LEN;
         $hLen   += length $self->options if $self->options;
         $self->off($hLen / 4);
      }

      $self->_computeHeaderLength;
      $self->_computeOptionsLength;
   }

   return $self;
}

sub recv {
   my ($self, $l3) = @_;

   my $src   = $l3->src;
   my $dst   = $l3->dst;
   my $sport = $self->src;
   my $dport = $self->dst;
   my $flags = $self->flags;
   my $ack   = $self->seq + 1;
   
   for ($Net::Pkt::Dump->frames) {
      if ($_->isFrameTcp) {
         if ($_->l3->src eq $dst
         &&  $_->l3->dst eq $src
         &&  $_->l4->src == $dport
         &&  $_->l4->dst == $sport
         && ($_->l4->ack == $ack || $_->l4->haveFlagRst)) {
            return $_;
         }
      }
   }

   return undef;
}

sub pack {
   my $self = shift;

   my $offX2Flags =
   ($self->off << 12) | (0x0f00 & ($self->x2 << 8)) | (0x00ff & $self->flags);

   $self->raw(
      pack('nnNNnnSn',
         $self->src,
         $self->dst,
         $self->seq,
         $self->ack,
         $offX2Flags,
         $self->win,
         $self->checksum,
         $self->urp,
      ),
   );

   $self->raw($self->raw. pack('a*', $self->options)) if $self->optionsLength;
   $self->rawLength(length $self->raw);
}

sub unpack {
   my $self = shift;

   my ($src, $dst, $seq, $ack, $offX2Flags, $win, $checksum, $urp, $payload) =
      unpack('nnNNnnnn a*', $self->raw);

   $self->src($src);
   $self->dst($dst);
   $self->seq($seq);
   $self->ack($ack);
   $self->off(($offX2Flags & 0xf000) >> 12);
   $self->x2(($offX2Flags & 0x0f00) >> 8);
   $self->flags($offX2Flags & 0x00ff);
   $self->win($win);
   $self->checksum($checksum);
   $self->urp($urp);
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
   $self->headerLength($self->off * 4);
}

sub _computeOptionsLength {
   my $self = shift;
   $self->headerLength > NETPKT_TCP_HDR_LEN
      ? $self->optionsLength($self->headerLength - NETPKT_TCP_HDR_LEN)
      : $self->optionsLength(0);
}

sub computeLengths {
   my $self = shift;

   $self->_computeHeaderLength;
   $self->_computeOptionsLength;
}

sub computeChecksums {
   my $self = shift;
   my ($l2, $l3, $l4, $l7) = @_;

   my $offX2Flags =
   ($self->off << 12) | (0x0f00 & ($self->x2 << 8)) | (0x00ff & $self->flags);

   my $phpkt =
      CORE::pack('a4a4CCn nnNNnnSn',
         inet_aton($l3->src),
         inet_aton($l3->dst),
         0,
         $l3->protocol,
         $l3->len - $l3->headerLength,
         $self->src,
         $self->dst,
         $self->seq,
         $self->ack,
         $offX2Flags,
         $self->win,
         $self->checksum,
         $self->urp,
      );
   $phpkt .= CORE::pack('a*', $self->options) if $self->options;
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
      "$l:+$i: seq:0x%.8x  win:%d  [%d => %d]\n".
      "$l: $i: ack:0x%.8x  flags:0x%.2x  urp:0x%.4x  checksum:0x%.4x\n".
      "$l: $i: size:%d  header:%d  options:%d\n",
         $self->seq,
         $self->win,
         $self->src,
         $self->dst,
         $self->ack,
         $self->flags,
         $self->urp,
         $self->checksum,
         $self->headerLength,
         NETPKT_TCP_HDR_LEN,
         $self->optionsLength,
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

sub _haveFlag   { shift->flags & shift                  }
sub haveFlagFin { shift->_haveFlag(NETPKT_TCP_FLAG_FIN) }
sub haveFlagSyn { shift->_haveFlag(NETPKT_TCP_FLAG_SYN) }
sub haveFlagRst { shift->_haveFlag(NETPKT_TCP_FLAG_RST) }
sub haveFlagPsh { shift->_haveFlag(NETPKT_TCP_FLAG_PSH) }
sub haveFlagAck { shift->_haveFlag(NETPKT_TCP_FLAG_ACK) }
sub haveFlagUrg { shift->_haveFlag(NETPKT_TCP_FLAG_URG) }
sub haveFlagEce { shift->_haveFlag(NETPKT_TCP_FLAG_ECE) }
sub haveFlagCwr { shift->_haveFlag(NETPKT_TCP_FLAG_CWR) }

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
