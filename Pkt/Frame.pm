package Net::Pkt::Frame;

# $Date: 2004/09/03 19:36:35 $
# $Revision: 1.55.2.7 $

use warnings;
use strict;
use Carp;

require Exporter;
require Net::Pkt;
our @ISA = qw(Net::Pkt Exporter);
our @EXPORT_OK = qw(
   NETPKT_LAYER
   NETPKT_LAYER_ETH
   NETPKT_LAYER_ARP
   NETPKT_LAYER_IPv4
   NETPKT_LAYER_TCP
   NETPKT_LAYER_UDP
   NETPKT_LAYER_ICMPv4
   NETPKT_LAYER_7
   NETPKT_LAYER_NONE
   NETPKT_LAYER_UNKNOWN
);

use Net::Pkt::LayerETH;
use Net::Pkt::LayerARP;
use Net::Pkt::LayerIPv4;
use Net::Pkt::LayerTCP;
use Net::Pkt::LayerUDP;
use Net::Pkt::LayerICMPv4;
use Net::Pkt::Layer7;

use constant NETPKT_LAYER         => 'Net::Pkt::Layer';
use constant NETPKT_LAYER_ETH     => 'ETH';
use constant NETPKT_LAYER_ARP     => 'ARP';
use constant NETPKT_LAYER_IPv4    => 'IPv4';
use constant NETPKT_LAYER_TCP     => 'TCP';
use constant NETPKT_LAYER_UDP     => 'UDP';
use constant NETPKT_LAYER_ICMPv4  => 'ICMPv4';
use constant NETPKT_LAYER_7       => '7';
use constant NETPKT_LAYER_NONE    => 'NONE';
use constant NETPKT_LAYER_UNKNOWN => 'UNKNOWN';

use constant NETPKT_L_2       => 'L2';
use constant NETPKT_L_3       => 'L3';
use constant NETPKT_L_4       => 'L4';
use constant NETPKT_L_7       => 'L7';
use constant NETPKT_L_UNKNOWN => 'L?';

BEGIN {
   # Some aliases
   *ipFlags = \&ipOff;
}

our @AccessorsScalar = qw(
   l2
   l3
   l4
   l7
   raw
   rawLength
   payload
   payloadLength
);

sub new {
   my $self = shift->SUPER::new(@_);

   croak("@{[(caller(0))[3]]}: you must either pass `raw' parameter or some ".
         "`l[N]' parameters (example: @{[(caller(0))[3]]}(l2 => \$l2, l3 => ".
         "\$l3)")
      unless $self->raw || ($self->l2 || $self->l3 || $self->l4 || $self->l7);

   $self->raw
      ? return $self->_decodeFromNetwork
      : return $self->_encodeToNetwork;
}

sub _decodeFromNetwork {
   my $self = shift;

   my $nextLayer;
   while (1) {
      # We must begin with something to identify next layers
      my $l2 = Net::Pkt::LayerETH->new(raw => $self->raw);
      $l2->isTypeIpv4 || $l2->isTypeArp
         ? $self->l2($l2)
         : return undef;

      last if $self->l2->encapsulate eq NETPKT_LAYER_NONE;
      $nextLayer = NETPKT_LAYER. $self->l2->encapsulate;

      # Here, the next layer can't be UNKNOWN
      $self->l3($nextLayer->new(raw => $l2->payload));

      # But here, it can be
      return undef if $self->l3->encapsulate eq NETPKT_LAYER_UNKNOWN;

      # Because of some broken stacks or device driver
      $self->_fixWithIpLen if $self->isFrameIpv4;

      last if $self->l3->encapsulate eq NETPKT_LAYER_NONE;
      $nextLayer = NETPKT_LAYER. $self->l3->encapsulate;

      $self->l4($nextLayer->new(raw => $self->l3->payload));

      # Here, no check; it is just raw layer 7 application data
      last if $self->l4->encapsulate eq NETPKT_LAYER_NONE;
      $nextLayer = NETPKT_LAYER. $self->l4->encapsulate;

      $self->l7($nextLayer->new(raw => $self->l4->payload));

      last;
   }

   $self->rawLength(length $self->raw);

   return $self;
}

sub _encodeToNetwork {
   my $self = shift;

   # They all have info about other layers, to do their work
   if ($self->l2) {
      $self->l2->computeLengths(undef, $self->l3, $self->l4, $self->l7);
      $self->l2->computeChecksums(undef, $self->l3, $self->l4, $self->l7);
      $self->l2->pack;
   }

   if ($self->l3) {
      $self->l3->computeLengths($self->l2, undef, $self->l4, $self->l7);
      $self->l3->computeChecksums($self->l2, undef, $self->l4, $self->l7);
      $self->l3->pack;
   }

   if ($self->l4) {
      $self->l4->computeLengths($self->l2, $self->l3, undef, $self->l7);
      $self->l4->computeChecksums($self->l2, $self->l3, undef, $self->l7);
      $self->l4->pack;
   }

   if ($self->l7) {
      $self->l7->computeLengths($self->l2, $self->l3, $self->l4, undef);
      $self->l7->computeChecksums($self->l2, $self->l3, $self->l4, undef);
      $self->l7->pack;
   }

   my $raw;
   $raw .= $self->l2->raw if $self->l2;
   $raw .= $self->l3->raw if $self->l3;
   $raw .= $self->l4->raw if $self->l4;
   $raw .= $self->l7->raw if $self->l7;
   $self->raw($raw) if $raw;

   $self->raw
      ? $self->rawLength(length $raw)
      : $self->rawLength(0);

   return $self;
}

# Will wipe out the trailing memory disclosure found in the packet
sub _fixWithIpLen {
   my $self = shift;
   my $truncated =
      substr($self->l3->payload, 0, $self->l3->len - $self->l3->headerLength);
   $self->l3->payload($truncated);
}

sub send {
   my $self = shift;

   croak("@{[(caller(0))[3]]}: \$Net::Pkt::Desc variable not set")
      unless $Net::Pkt::Desc;

   if ($Net::Pkt::Debug && $Net::Pkt::Debug >= 3) {
      if ($self->isFrameIpv4) {
         $self->debugPrint(
            "send: @{[$self->l3->is]}: size:@{[$self->ipLen]}  ".
            "@{[$self->ipSrc]} => @{[$self->ipDst]}"
         );
      }
      if ($self->isFrameTcp || $self->isFrameUdp) {
         $self->debugPrint( 
            "send: @{[$self->l4->is]}: ".
            "@{[$self->l4->src]} => @{[$self->l4->dst]}"
         );
      }
   }

   $Net::Pkt::Desc->send($self->raw);
}

sub getFilter {
   my $self = shift;
   my $filter;

   # L3 filtering
   if ($self->l3) {
      if ($self->isFrameIpv4) {
         $filter .= "src host @{[$self->ipDst]}".
                    " and dst host @{[$self->ipSrc]}";
      }
      elsif ($self->isFrameArp) {
         $filter .= "arp";
      }
   }
    
   # L4 filtering
   if ($self->l4) {
      $filter .= " and " if $filter;
      
      if ($self->isFrameTcp) { 
         $filter .= "tcp and".
                    " src port @{[$self->tcpDst]}".
                    " and dst port @{[$self->tcpSrc]}";
      }
      elsif ($self->isFrameUdp) {
         $filter .= "udp and".
                    " src port @{[$self->udpDst]}".
                    " and dst port @{[$self->udpSrc]}".
                    " or icmp";
      }
      elsif ($self->isFrameIcmpv4) { 
         $filter .= "icmp";
      }
   }
    
   return $filter;
}

sub recv {
   my $self = shift;

   croak("@{[(caller(0))[3]]}: \$Net::Pkt::Dump variable not set")
      unless $Net::Pkt::Dump;

   # XXX: rewrite in more Perlish
   if ($self->isFrameTcp || $self->isFrameUdp || $self->isFrameIcmpv4) {
      return $self->l4->recv($self->l3);
   }
   elsif ($self->isFrameArp) {
      return $self->l3->recv;
   }
   elsif ($self->isFrame7) {
      return $self->l7->recv(@_);
   }
   else {
      croak("@{[(caller(0))[3]]}: not implemented for this Layer");
   }

   return undef;
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

sub _isFrame {
   my ($self, $layer, $type) = @_;
   return 0 unless defined $layer;
   $layer && $layer->is eq $type
      ? return 1
      : return 0;
}

sub isFrameEth {
   my $self = shift;
   $self->_isFrame($self->l2, NETPKT_LAYER_ETH);
}

sub isFrameArp {
   my $self = shift;
   $self->_isFrame($self->l3, NETPKT_LAYER_ARP);
}

sub isFrameIpv4 {
   my $self = shift;
   $self->_isFrame($self->l3, NETPKT_LAYER_IPv4);
}
sub isFrameIp { return shift->isFrameIpv4; } # XXX: to handle IPv6

sub isFrameTcp {
   my $self = shift;
   $self->_isFrame($self->l4, NETPKT_LAYER_TCP);
}

sub isFrameUdp {
   my $self = shift;
   $self->_isFrame($self->l4, NETPKT_LAYER_UDP);
}

sub isFrameIcmpv4 {
   my $self = shift;
   $self->_isFrame($self->l4, NETPKT_LAYER_ICMPv4);
}

sub isFrame7 {
   my $self = shift;
   $self->_isFrame($self->l7, NETPKT_LAYER_7);
}

#
# L2 helpers
#

# ETH

sub ethPrint { shift->l2->print }
sub ethDump  { shift->l2->dump  }

sub ethSrc  { shift->l2->src  }
sub ethDst  { shift->l2->dst  }
sub ethType { shift->l2->type }

sub ethIsTypeIpv4 { shift->l2->isTypeIpv4 }
sub ethIsTypeArp  { shift->l2->isTypeArp  }

#
# L3 helpers
#

# IPv4

sub ipPrint { shift->l3->print }
sub ipDump  { shift->l3->dump  }

sub ipHeaderLength  { shift->l3->headerLength  }
sub ipOptionsLength { shift->l3->optionsLength }

sub ipId        { shift->l3->id       }
sub ipHlen      { shift->l3->hlen     }
sub ipLen       { shift->l3->len      }
sub ipTos       { shift->l3->tos      }
sub ipVer       { shift->l3->ver      }
sub ipOff       { shift->l3->off      }
sub ipChecksum  { shift->l3->checksum }
sub ipProtocol  { shift->l3->protocol }
sub ipSrc       { shift->l3->src      }
sub ipDst       { shift->l3->dst      }
sub ipTtl       { shift->l3->ttl      }
sub ipOptions   { shift->l3->options  }

sub ipHaveFlagDf { shift->l3->haveFlagDf }
sub ipHaveFlagMf { shift->l3->haveFlagMf }
sub ipHaveFlagRf { shift->l3->haveFlagRf }

sub ipIsV4 { shift->l3->isV4 }

# ARP

sub arpPrint { shift->l3->print }
sub arpDump  { shift->l3->print }

sub arpHType   { shift->l3->hType   }
sub arpPType   { shift->l3->pType   }
sub arpHSize   { shift->l3->hSize   }
sub arpPSize   { shift->l3->pSize   }
sub arpOpCode  { shift->l3->opCode  }
sub arpSrc     { shift->l3->src     }
sub arpDst     { shift->l3->dst     }
sub arpSrcIp   { shift->l3->srcIp   }
sub arpDstIp   { shift->l3->dstIp   }
sub arpPadding { shift->l3->padding }

#
# L4 helpers
#

# TCP

sub tcpPrint { shift->l4->print }
sub tcpDump  { shift->l4->dump  }

sub tcpHeaderLength  { shift->l4->headerLength  }
sub tcpOptionsLength { shift->l4->optionsLength }

sub tcpSrc      { shift->l4->src      }
sub tcpDst      { shift->l4->dst      }
sub tcpSeq      { shift->l4->seq      }
sub tcpAck      { shift->l4->ack      }
sub tcpOff      { shift->l4->off      }
sub tcpX2       { shift->l4->x2       }
sub tcpUrp      { shift->l4->urp      }
sub tcpChecksum { shift->l4->checksum }
sub tcpFlags    { shift->l4->flags    }
sub tcpWin      { shift->l4->win      }
sub tcpOptions  { shift->l4->options  }

sub tcpHaveFlagSyn { shift->l4->haveFlagSyn }
sub tcpHaveFlagAck { shift->l4->haveFlagAck }
sub tcpHaveFlagFin { shift->l4->haveFlagFin }
sub tcpHaveFlagRst { shift->l4->haveFlagRst }
sub tcpHaveFlagPsh { shift->l4->haveFlagPsh }
sub tcpHaveFlagUrg { shift->l4->haveFlagUrg }
sub tcpHaveFlagEce { shift->l4->haveFlagEce }
sub tcpHaveFlagCwr { shift->l4->haveFlagCwr }

# UDP

sub udpPrint { shift->l4->print }
sub udpDump  { shift->l4->dump  }

sub udpHeaderLength { shift->l4->headerLength }
sub udpTotalLength  { shift->l4->totalLength  }

sub udpSrc      { shift->l4->src      }
sub udpDst      { shift->l4->dst      }
sub udpLen      { shift->l4->len      }
sub udpChecksum { shift->l4->Checksum }

#
# ICMPv4
#

sub icmpPrint { shift->l4->print }
sub icmpDump  { shift->l4->dump  }

sub icmpHeaderLength { shift->l4->headerLength }
sub icmpDataLength   { shift->l4->dataLength   }

sub icmpType               { shift->l4->type               }
sub icmpCode               { shift->l4->code               }
sub icmpChecksum           { shift->l4->checksum           }
sub icmpIdentifier         { shift->l4->identifier         }
sub icmpSequenceNumber     { shift->l4->sequenceNumber     }
sub icmpOriginateTimestamp { shift->l4->originateTimestamp }
sub icmpReceiveTimestamp   { shift->l4->receiveTimestamp   }
sub icmpTransmitTimestamp  { shift->l4->transmitTimestamp  }
sub icmpData               { shift->l4->data               }

#
# L7 helpers
#

sub l7Print { shift->l7->print }
sub l7Dump  { shift->l7->dump  }

sub l7DataLength { shift->l7->dataLength }

sub l7Data { shift->l7->data }

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
