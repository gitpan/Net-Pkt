package Net::Pkt::LayerICMPv4;

# $Date: 2004/09/23 17:09:42 $
# $Revision: 1.1.2.7 $

use strict;
use warnings;
use Carp;

require Exporter;
require Net::Pkt::Layer4;
our @ISA = qw(Net::Pkt::Layer4 Exporter);
our @EXPORT_OK = qw( 
   NETPKT_ICMPv4_HDR_LEN
   NETPKT_ICMPv4_TYPE_ECHO_REQUEST
   NETPKT_ICMPv4_TYPE_ECHO_REPLY
   NETPKT_ICMPv4_TYPE_TIMESTAMP_REQUEST
   NETPKT_ICMPv4_TYPE_TIMESTAMP_REPLY
   NETPKT_ICMPv4_TYPE_INFORMATION_REQUEST
   NETPKT_ICMPv4_TYPE_INFORMATION_REPLY
   NETPKT_ICMPv4_TYPE_ADDRESS_MASK_REQUEST
   NETPKT_ICMPv4_TYPE_ADDRESS_MASK_REPLY
   NETPKT_ICMPv4_CODE_ZERO
);

use Socket;

use constant NETPKT_ICMPv4_HDR_LEN => 8;

use constant NETPKT_ICMPv4_CODE_ZERO => 0;

use constant NETPKT_ICMPv4_TYPE_DESTINATION_UNREACHABLE => 3;
use constant NETPKT_ICMPv4_CODE_NETWORK                 => 0;
use constant NETPKT_ICMPv4_CODE_HOST                    => 1;
use constant NETPKT_ICMPv4_CODE_PROTOCOL                => 2;
use constant NETPKT_ICMPv4_CODE_PORT                    => 3;
use constant NETPKT_ICMPv4_CODE_FRAGMENTATION_NEEDED    => 4;
use constant NETPKT_ICMPv4_CODE_SOURCE_ROUTE_FAILED     => 5;

use constant NETPKT_ICMPv4_TYPE_TIME_EXCEEDED           => 11;
use constant NETPKT_ICMPv4_CODE_TTL_IN_TRANSIT          => 0;
use constant NETPKT_ICMPv4_CODE_FRAGMENT_REASSEMBLY     => 1;

use constant NETPKT_ICMPv4_TYPE_PARAMETER_PROBLEM => 12;
use constant NETPKT_ICMPv4_CODE_POINTER           => 0;

use constant NETPKT_ICMPv4_TYPE_SOURCE_QUENCH => 4;

use constant NETPKT_ICMPv4_TYPE_REDIRECT            => 5;
use constant NETPKT_ICMPv4_CODE_FOR_NETWORK         => 0;
use constant NETPKT_ICMPv4_CODE_FOR_HOST            => 1;
use constant NETPKT_ICMPv4_CODE_FOR_TOS_AND_NETWORK => 2;
use constant NETPKT_ICMPv4_CODE_FOR_TOS_AND_HOST    => 3;

use constant NETPKT_ICMPv4_TYPE_ECHO_REQUEST => 8;
use constant NETPKT_ICMPv4_TYPE_ECHO_REPLY   => 0;

use constant NETPKT_ICMPv4_TYPE_TIMESTAMP_REQUEST => 13;
use constant NETPKT_ICMPv4_TYPE_TIMESTAMP_REPLY   => 14;

use constant NETPKT_ICMPv4_TYPE_INFORMATION_REQUEST => 15;
use constant NETPKT_ICMPv4_TYPE_INFORMATION_REPLY   => 16;

use constant NETPKT_ICMPv4_TYPE_ADDRESS_MASK_REQUEST => 17; # RFC 950
use constant NETPKT_ICMPv4_TYPE_ADDRESS_MASK_REPLY   => 18; # RFC 950

our @AccessorsScalar = qw(
   type
   code
   checksum
   identifier
   sequenceNumber
   originateTimestamp
   receiveTimestamp
   transmitTimestamp
   addressMask
   data
   headerLength
   dataLength
);

sub new {
   my $self = shift->SUPER::new(
      type               => 0,
      code               => 0,
      checksum           => 0,
      identifier         => Net::Pkt->getRandom16bitsInt,
      sequenceNumber     => Net::Pkt->getRandom16bitsInt,
      originateTimestamp => Net::Pkt->getRandom32bitsInt,
      receiveTimestamp   => 0,
      transmitTimestamp  => 0,
      addressMask        => 0,
      data               => "",
      @_,
   );

   unless ($self->raw) {
      $self->_computeDataLength;
      $self->_computeHeaderLength;
   }

   return $self;
}

sub recv {
   my ($self, $l3) = @_;

   for ($Net::Pkt::Dump->frames) {
      if ($_->isFrameIcmpv4 && $_->l3->src eq $l3->dst) {
         if ($self->type  == NETPKT_ICMPv4_TYPE_ECHO_REQUEST
         &&  $_->l4->type == NETPKT_ICMPv4_TYPE_ECHO_REPLY) {
            return $_;
         }
         elsif ($self->type  == NETPKT_ICMPv4_TYPE_TIMESTAMP_REQUEST
            &&  $_->l4->type == NETPKT_ICMPv4_TYPE_TIMESTAMP_REPLY) {
            return $_;
         }
         elsif ($self->type  == NETPKT_ICMPv4_TYPE_INFORMATION_REQUEST
            &&  $_->l4->type == NETPKT_ICMPv4_TYPE_INFORMATION_REPLY) {
            return $_;
         }
         elsif ($self->type  == NETPKT_ICMPv4_TYPE_ADDRESS_MASK_REQUEST
            &&  $_->l4->type == NETPKT_ICMPv4_TYPE_ADDRESS_MASK_REPLY) {
            return $_;
         }
      }
   }

   return undef;
}

sub _packError {
   warn("@{[(caller(0))[3]]}: unknown ICMPv4 type: @{[shift->type]}\n");
   return undef;
}

sub _packEcho {
   my $self = shift;
   return pack('nn', $self->identifier, $self->sequenceNumber);
}

sub _packTimestamp {
   my $self = shift;
   return pack('nnNNN',
      $self->identifier,
      $self->sequenceNumber,
      $self->originateTimestamp,
      $self->receiveTimestamp,
      $self->transmitTimestamp,
   );
}

# It has same fields as ICMP echo request
sub _packInformation { return shift->_packEcho }

sub _packAddressMask {
   my $self = shift;
   return
      pack('nnN', $self->identifier, $self->sequenceNumber, $self->addressMask);
}

my $packTypes = {
   NETPKT_ICMPv4_TYPE_ECHO_REQUEST()         => '_packEcho',
   NETPKT_ICMPv4_TYPE_ECHO_REPLY()           => '_packEcho',
   NETPKT_ICMPv4_TYPE_TIMESTAMP_REQUEST()    => '_packTimestamp',
   NETPKT_ICMPv4_TYPE_TIMESTAMP_REPLY()      => '_packTimestamp',
   NETPKT_ICMPv4_TYPE_INFORMATION_REQUEST()  => '_packInformation',
   NETPKT_ICMPv4_TYPE_INFORMATION_REPLY()    => '_packInformation',
   NETPKT_ICMPv4_TYPE_ADDRESS_MASK_REQUEST() => '_packAddressMask',
   NETPKT_ICMPv4_TYPE_ADDRESS_MASK_REPLY()   => '_packAddressMask',
};

sub pack {
   my $self = shift;

   $self->raw(
      pack('CCS',
         $self->type,
         $self->code,
         $self->checksum,
      ),
   );

   my $sub = \&{$packTypes->{$self->type} || '_packError'};
   my $raw = $self->$sub;
   $raw   .= pack('a*', $self->data) if $self->data;

   $self->raw($self->raw. $raw);
   $self->rawLength(length $self->raw);

   $self->computeLengths;
}

my $unpackTypes = {
   NETPKT_ICMPv4_TYPE_ECHO_REQUEST()         => '_unpackEcho',
   NETPKT_ICMPv4_TYPE_ECHO_REPLY()           => '_unpackEcho',
   NETPKT_ICMPv4_TYPE_TIMESTAMP_REQUEST()    => '_unpackTimestamp',
   NETPKT_ICMPv4_TYPE_TIMESTAMP_REPLY()      => '_unpackTimestamp',
   NETPKT_ICMPv4_TYPE_INFORMATION_REQUEST()  => '_unpackInformation',
   NETPKT_ICMPv4_TYPE_INFORMATION_REPLY()    => '_unpackInformation',
   NETPKT_ICMPv4_TYPE_ADDRESS_MASK_REQUEST() => '_unpackAddressMask',
   NETPKT_ICMPv4_TYPE_ADDRESS_MASK_REPLY()   => '_unpackAddressMask',
};

sub _unpackError {
   warn("@{[(caller(0))[3]]}: unknown ICMPv4 type: @{[shift->type]}\n");
   return undef;
}

sub _unpackEcho {
   my $self = shift;
   my ($id, $seq, $data) = unpack('nn a*', $self->payload);
   return {
      identifier     => $id,
      sequenceNumber => $seq,
      data           => $data,
   };
}

sub _unpackTimestamp {
   my $self = shift;
   my ($id, $seq, $orig, $recv, $trans, $data) =
      unpack('nnNNN a*', $self->payload);
   return {
      identifier         => $id,
      sequenceNumber     => $seq,
      originateTimestamp => $orig,
      receiveTimestamp   => $recv,
      transmitTimestamp  => $trans,
      data               => $data,
   };
}

sub _unpackInformation { return shift->_unpackEcho }

sub _unpackAddressMask {
   my $self = shift;
   my ($id, $seq, $mask, $data) = unpack('nnN a*', $self->payload);
   return {
      identifier     => $id,
      sequenceNumber => $seq,
      addressMask    => $mask,
      data           => $data,
   };
}

sub unpack {
   my $self = shift;

   my ($type, $code, $checksum, $payload) = unpack('CCS a*', $self->raw);

   $self->type($type);
   $self->code($code);
   $self->checksum($checksum);
   $self->payload($payload);

   # unpack specific ICMPv4 types
   my $sub = \&{$unpackTypes->{$self->type} || '_unpackError'};
   my $href = $self->$sub;
   $self->$_($href->{$_}) for keys %$href;

   # payload has been handled by previous chunk of code
   $self->payload(undef);
   $self->payloadLength(0);

   $self->computeLengths;
}

sub _computeDataLength {
   my $self = shift;
   $self->data
      ? $self->dataLength(length $self->data)
      : $self->dataLength(0);
}

sub _computeHeaderLength {
   my $self = shift;

   my $hdrLengths = {
      NETPKT_ICMPv4_TYPE_ECHO_REQUEST()         => 8  + $self->dataLength,
      NETPKT_ICMPv4_TYPE_ECHO_REPLY()           => 8  + $self->dataLength,
      NETPKT_ICMPv4_TYPE_TIMESTAMP_REQUEST()    => 20 + $self->dataLength,
      NETPKT_ICMPv4_TYPE_TIMESTAMP_REPLY()      => 20 + $self->dataLength,
      NETPKT_ICMPv4_TYPE_INFORMATION_REQUEST()  => 8  + $self->dataLength,
      NETPKT_ICMPv4_TYPE_INFORMATION_REPLY()    => 8  + $self->dataLength,
      NETPKT_ICMPv4_TYPE_ADDRESS_MASK_REQUEST() => 8  + $self->dataLength,
      NETPKT_ICMPv4_TYPE_ADDRESS_MASK_REPLY()   => 8  + $self->dataLength,
   };

   $self->headerLength($hdrLengths->{$self->type});
}

sub computeLengths {
   my $self = shift;
   $self->_computeDataLength;
   $self->_computeHeaderLength;
}

sub computeChecksums {
   my $self = shift;

   my $sub = \&{$packTypes->{$self->type} || '_packError'};
   my $raw = $self->$sub;
   $raw   .= CORE::pack('a*', $self->data) if $self->data;

   $self->checksum(
      Net::Pkt->inetChecksum(
         CORE::pack('CCn', $self->type, $self->code, 0). $raw
      ),
   );
}

# XXX: maybe ICMP can be made to encap IPv4
sub encapsulate { Net::Pkt::Frame::NETPKT_LAYER_NONE() }

sub print {
   my $self = shift;

   my $i = $self->is;
   my $l = $self->layer;
   printf
      "$l:+$i: type:%d  code:%d  checksum:0x%.4x  size:%d\n",
         $self->type,
         $self->code,
         $self->checksum,
         $self->headerLength,
   ;
   printf "$l: $i: dataLength:%d  data:%s\n",
      $self->dataLength,
      CORE::unpack('H*', $self->data),
         if $self->data
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

sub _isType                  { shift->type == shift() ? 1 : 0 }
sub isTypeEchoRequest        { shift->_isType(NETPKT_ICMPv4_TYPE_ECHO_REQUEST) }
sub isTypeEchoReply          { shift->_isType(NETPKT_ICMPv4_TYPE_ECHO_REPLY)   }
sub isTypeTimestampRequest   { shift->_isType(NETPKT_ICMPv4_TYPE_TIMESTAMP_REQUEST)    }
sub isTypeTimestampReply     { shift->_isType(NETPKT_ICMPv4_TYPE_TIMESTAMP_REPLY)      }
sub isTypeInformationRequest { shift->_isType(NETPKT_ICMPv4_TYPE_INFORMATION_REQUEST)  }
sub isTypeInformationReply   { shift->_isType(NETPKT_ICMPv4_TYPE_INFORMATION_REPLY)    }
sub isTypeAddressMaskRequest { shift->_isType(NETPKT_ICMPv4_TYPE_ADDRESS_MASK_REQUEST) }
sub isTypeAddressMaskReply   { shift->_isType(NETPKT_ICMPv4_TYPE_ADDRESS_MASK_REPLY)   }

1;

__END__

=head1 RFC 792 - Internet Control Message Protocol

Network Working Group                                          J. Postel
Request for Comments:  792                                           ISI
                                                          September 1981
Updates:  RFCs 777, 760
Updates:  IENs 109, 128

                   INTERNET CONTROL MESSAGE PROTOCOL

                         DARPA INTERNET PROGRAM
                         PROTOCOL SPECIFICATION



Introduction

   The Internet Protocol (IP) [1] is used for host-to-host datagram
   service in a system of interconnected networks called the
   Catenet [2].  The network connecting devices are called Gateways.
   These gateways communicate between themselves for control purposes
   via a Gateway to Gateway Protocol (GGP) [3,4].  Occasionally a
   gateway or destination host will communicate with a source host, for
   example, to report an error in datagram processing.  For such
   purposes this protocol, the Internet Control Message Protocol (ICMP),
   is used.  ICMP, uses the basic support of IP as if it were a higher
   level protocol, however, ICMP is actually an integral part of IP, and
   must be implemented by every IP module.

   ICMP messages are sent in several situations:  for example, when a
   datagram cannot reach its destination, when the gateway does not have
   the buffering capacity to forward a datagram, and when the gateway
   can direct the host to send traffic on a shorter route.

   The Internet Protocol is not designed to be absolutely reliable.  The
   purpose of these control messages is to provide feedback about
   problems in the communication environment, not to make IP reliable.
   There are still no guarantees that a datagram will be delivered or a
   control message will be returned.  Some datagrams may still be
   undelivered without any report of their loss.  The higher level
   protocols that use IP must implement their own reliability procedures
   if reliable communication is required.

   The ICMP messages typically report errors in the processing of
   datagrams.  To avoid the infinite regress of messages about messages
   etc., no ICMP messages are sent about ICMP messages.  Also ICMP
   messages are only sent about errors in handling fragment zero of
   fragemented datagrams.  (Fragment zero has the fragment offeset equal
   zero).







                                                                [Page 1]

                                                          September 1981
RFC 792



Message Formats

   ICMP messages are sent using the basic IP header.  The first octet of
   the data portion of the datagram is a ICMP type field; the value of
   this field determines the format of the remaining data.  Any field
   labeled "unused" is reserved for later extensions and must be zero
   when sent, but receivers should not use these fields (except to
   include them in the checksum).  Unless otherwise noted under the
   individual format descriptions, the values of the internet header
   fields are as follows:

   Version

      4

   IHL

      Internet header length in 32-bit words.

   Type of Service

      0

   Total Length

      Length of internet header and data in octets.

   Identification, Flags, Fragment Offset

      Used in fragmentation, see [1].

   Time to Live

      Time to live in seconds; as this field is decremented at each
      machine in which the datagram is processed, the value in this
      field should be at least as great as the number of gateways which
      this datagram will traverse.

   Protocol

      ICMP = 1

   Header Checksum

      The 16 bit one's complement of the one's complement sum of all 16
      bit words in the header.  For computing the checksum, the checksum
      field should be zero.  This checksum may be replaced in the
      future.


[Page 2]                                                                

September 1981                                                          
RFC 792



   Source Address

      The address of the gateway or host that composes the ICMP message.
      Unless otherwise noted, this can be any of a gateway's addresses.

   Destination Address

      The address of the gateway or host to which the message should be
      sent.









































                                                                [Page 3]

                                                          September 1981
RFC 792



Destination Unreachable Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             unused                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IP Fields:

   Destination Address

      The source network and address from the original datagram's data.

   ICMP Fields:

   Type

      3

   Code

      0 = net unreachable;

      1 = host unreachable;

      2 = protocol unreachable;

      3 = port unreachable;

      4 = fragmentation needed and DF set;

      5 = source route failed.

   Checksum

      The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type.
      For computing the checksum , the checksum field should be zero.
      This checksum may be replaced in the future.

   Internet Header + 64 bits of Data Datagram

      The internet header plus the first 64 bits of the original


[Page 4]                                                                

September 1981                                                          
RFC 792



      datagram's data.  This data is used by the host to match the
      message to the appropriate process.  If a higher level protocol
      uses port numbers, they are assumed to be in the first 64 data
      bits of the original datagram's data.

   Description

      If, according to the information in the gateway's routing tables,
      the network specified in the internet destination field of a
      datagram is unreachable, e.g., the distance to the network is
      infinity, the gateway may send a destination unreachable message
      to the internet source host of the datagram.  In addition, in some
      networks, the gateway may be able to determine if the internet
      destination host is unreachable.  Gateways in these networks may
      send destination unreachable messages to the source host when the
      destination host is unreachable.

      If, in the destination host, the IP module cannot deliver the
      datagram  because the indicated protocol module or process port is
      not active, the destination host may send a destination
      unreachable message to the source host.

      Another case is when a datagram must be fragmented to be forwarded
      by a gateway yet the Don't Fragment flag is on.  In this case the
      gateway must discard the datagram and may return a destination
      unreachable message.

      Codes 0, 1, 4, and 5 may be received from a gateway.  Codes 2 and
      3 may be received from a host.





















                                                                [Page 5]

                                                          September 1981
RFC 792



Time Exceeded Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             unused                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IP Fields:

   Destination Address

      The source network and address from the original datagram's data.

   ICMP Fields:

   Type

      11

   Code

      0 = time to live exceeded in transit;

      1 = fragment reassembly time exceeded.

   Checksum

      The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type.
      For computing the checksum , the checksum field should be zero.
      This checksum may be replaced in the future.

   Internet Header + 64 bits of Data Datagram

      The internet header plus the first 64 bits of the original
      datagram's data.  This data is used by the host to match the
      message to the appropriate process.  If a higher level protocol
      uses port numbers, they are assumed to be in the first 64 data
      bits of the original datagram's data.

   Description

      If the gateway processing a datagram finds the time to live field


[Page 6]                                                                

September 1981                                                          
RFC 792



      is zero it must discard the datagram.  The gateway may also notify
      the source host via the time exceeded message.

      If a host reassembling a fragmented datagram cannot complete the
      reassembly due to missing fragments within its time limit it
      discards the datagram, and it may send a time exceeded message.

      If fragment zero is not available then no time exceeded need be
      sent at all.

      Code 0 may be received from a gateway.  Code 1 may be received
      from a host.






































                                                                [Page 7]

                                                          September 1981
RFC 792



Parameter Problem Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Pointer    |                   unused                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IP Fields:

   Destination Address

      The source network and address from the original datagram's data.

   ICMP Fields:

   Type

      12

   Code

      0 = pointer indicates the error.

   Checksum

      The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type.
      For computing the checksum , the checksum field should be zero.
      This checksum may be replaced in the future.

   Pointer

      If code = 0, identifies the octet where an error was detected.

   Internet Header + 64 bits of Data Datagram

      The internet header plus the first 64 bits of the original
      datagram's data.  This data is used by the host to match the
      message to the appropriate process.  If a higher level protocol
      uses port numbers, they are assumed to be in the first 64 data
      bits of the original datagram's data.




[Page 8]                                                                

September 1981                                                          
RFC 792



   Description

      If the gateway or host processing a datagram finds a problem with
      the header parameters such that it cannot complete processing the
      datagram it must discard the datagram.  One potential source of
      such a problem is with incorrect arguments in an option.  The
      gateway or host may also notify the source host via the parameter
      problem message.  This message is only sent if the error caused
      the datagram to be discarded.

      The pointer identifies the octet of the original datagram's header
      where the error was detected (it may be in the middle of an
      option).  For example, 1 indicates something is wrong with the
      Type of Service, and (if there are options present) 20 indicates
      something is wrong with the type code of the first option.

      Code 0 may be received from a gateway or a host.

































                                                                [Page 9]

                                                          September 1981
RFC 792



Source Quench Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             unused                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IP Fields:

   Destination Address

      The source network and address of the original datagram's data.

   ICMP Fields:

   Type

      4

   Code

      0

   Checksum

      The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type.
      For computing the checksum , the checksum field should be zero.
      This checksum may be replaced in the future.

   Internet Header + 64 bits of Data Datagram

      The internet header plus the first 64 bits of the original
      datagram's data.  This data is used by the host to match the
      message to the appropriate process.  If a higher level protocol
      uses port numbers, they are assumed to be in the first 64 data
      bits of the original datagram's data.

   Description

      A gateway may discard internet datagrams if it does not have the
      buffer space needed to queue the datagrams for output to the next
      network on the route to the destination network.  If a gateway


[Page 10]                                                               

September 1981                                                          
RFC 792



      discards a datagram, it may send a source quench message to the
      internet source host of the datagram.  A destination host may also
      send a source quench message if datagrams arrive too fast to be
      processed.  The source quench message is a request to the host to
      cut back the rate at which it is sending traffic to the internet
      destination.  The gateway may send a source quench message for
      every message that it discards.  On receipt of a source quench
      message, the source host should cut back the rate at which it is
      sending traffic to the specified destination until it no longer
      receives source quench messages from the gateway.  The source host
      can then gradually increase the rate at which it sends traffic to
      the destination until it again receives source quench messages.

      The gateway or host may send the source quench message when it
      approaches its capacity limit rather than waiting until the
      capacity is exceeded.  This means that the data datagram which
      triggered the source quench message may be delivered.

      Code 0 may be received from a gateway or a host.































                                                               [Page 11]

                                                          September 1981
RFC 792



Redirect Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Gateway Internet Address                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IP Fields:

   Destination Address

      The source network and address of the original datagram's data.

   ICMP Fields:

   Type

      5

   Code

      0 = Redirect datagrams for the Network.

      1 = Redirect datagrams for the Host.

      2 = Redirect datagrams for the Type of Service and Network.

      3 = Redirect datagrams for the Type of Service and Host.

   Checksum

      The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type.
      For computing the checksum , the checksum field should be zero.
      This checksum may be replaced in the future.

   Gateway Internet Address

      Address of the gateway to which traffic for the network specified
      in the internet destination network field of the original
      datagram's data should be sent.




[Page 12]                                                               

September 1981                                                          
RFC 792



   Internet Header + 64 bits of Data Datagram

      The internet header plus the first 64 bits of the original
      datagram's data.  This data is used by the host to match the
      message to the appropriate process.  If a higher level protocol
      uses port numbers, they are assumed to be in the first 64 data
      bits of the original datagram's data.

   Description

      The gateway sends a redirect message to a host in the following
      situation.  A gateway, G1, receives an internet datagram from a
      host on a network to which the gateway is attached.  The gateway,
      G1, checks its routing table and obtains the address of the next
      gateway, G2, on the route to the datagram's internet destination
      network, X.  If G2 and the host identified by the internet source
      address of the datagram are on the same network, a redirect
      message is sent to the host.  The redirect message advises the
      host to send its traffic for network X directly to gateway G2 as
      this is a shorter path to the destination.  The gateway forwards
      the original datagram's data to its internet destination.

      For datagrams with the IP source route options and the gateway
      address in the destination address field, a redirect message is
      not sent even if there is a better route to the ultimate
      destination than the next address in the source route.

      Codes 0, 1, 2, and 3 may be received from a gateway.






















                                                               [Page 13]

                                                          September 1981
RFC 792



Echo or Echo Reply Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-

   IP Fields:

   Addresses

      The address of the source in an echo message will be the
      destination of the echo reply message.  To form an echo reply
      message, the source and destination addresses are simply reversed,
      the type code changed to 0, and the checksum recomputed.

   IP Fields:

   Type

      8 for echo message;

      0 for echo reply message.

   Code

      0

   Checksum

      The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type.
      For computing the checksum , the checksum field should be zero.
      If the total length is odd, the received data is padded with one
      octet of zeros for computing the checksum.  This checksum may be
      replaced in the future.

   Identifier

      If code = 0, an identifier to aid in matching echos and replies,
      may be zero.

   Sequence Number


[Page 14]                                                               

September 1981                                                          
RFC 792



      If code = 0, a sequence number to aid in matching echos and
      replies, may be zero.

   Description

      The data received in the echo message must be returned in the echo
      reply message.

      The identifier and sequence number may be used by the echo sender
      to aid in matching the replies with the echo requests.  For
      example, the identifier might be used like a port in TCP or UDP to
      identify a session, and the sequence number might be incremented
      on each echo request sent.  The echoer returns these same values
      in the echo reply.

      Code 0 may be received from a gateway or a host.


































                                                               [Page 15]

                                                          September 1981
RFC 792



Timestamp or Timestamp Reply Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |      Code     |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Originate Timestamp                                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Receive Timestamp                                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Transmit Timestamp                                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IP Fields:

   Addresses

      The address of the source in a timestamp message will be the
      destination of the timestamp reply message.  To form a timestamp
      reply message, the source and destination addresses are simply
      reversed, the type code changed to 14, and the checksum
      recomputed.

   IP Fields:

   Type

      13 for timestamp message;

      14 for timestamp reply message.

   Code

      0

   Checksum

      The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type.
      For computing the checksum , the checksum field should be zero.
      This checksum may be replaced in the future.

   Identifier




[Page 16]                                                               

September 1981                                                          
RFC 792



      If code = 0, an identifier to aid in matching timestamp and
      replies, may be zero.

   Sequence Number

      If code = 0, a sequence number to aid in matching timestamp and
      replies, may be zero.

   Description

      The data received (a timestamp) in the message is returned in the
      reply together with an additional timestamp.  The timestamp is 32
      bits of milliseconds since midnight UT.  One use of these
      timestamps is described by Mills [5].

      The Originate Timestamp is the time the sender last touched the
      message before sending it, the Receive Timestamp is the time the
      echoer first touched it on receipt, and the Transmit Timestamp is
      the time the echoer last touched the message on sending it.

      If the time is not available in miliseconds or cannot be provided
      with respect to midnight UT then any time can be inserted in a
      timestamp provided the high order bit of the timestamp is also set
      to indicate this non-standard value.

      The identifier and sequence number may be used by the echo sender
      to aid in matching the replies with the requests.  For example,
      the identifier might be used like a port in TCP or UDP to identify
      a session, and the sequence number might be incremented on each
      request sent.  The destination returns these same values in the
      reply.

      Code 0 may be received from a gateway or a host.

















                                                               [Page 17]

                                                          September 1981
RFC 792



Information Request or Information Reply Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |      Code     |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IP Fields:

   Addresses

      The address of the source in a information request message will be
      the destination of the information reply message.  To form a
      information reply message, the source and destination addresses
      are simply reversed, the type code changed to 16, and the checksum
      recomputed.

   IP Fields:

   Type

      15 for information request message;

      16 for information reply message.

   Code

      0

   Checksum

      The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type.
      For computing the checksum , the checksum field should be zero.
      This checksum may be replaced in the future.

   Identifier

      If code = 0, an identifier to aid in matching request and replies,
      may be zero.

   Sequence Number

      If code = 0, a sequence number to aid in matching request and
      replies, may be zero.


[Page 18]                                                               

September 1981                                                          
RFC 792



   Description

      This message may be sent with the source network in the IP header
      source and destination address fields zero (which means "this"
      network).  The replying IP module should send the reply with the
      addresses fully specified.  This message is a way for a host to
      find out the number of the network it is on.

      The identifier and sequence number may be used by the echo sender
      to aid in matching the replies with the requests.  For example,
      the identifier might be used like a port in TCP or UDP to identify
      a session, and the sequence number might be incremented on each
      request sent.  The destination returns these same values in the
      reply.

      Code 0 may be received from a gateway or a host.


































                                                               [Page 19]

                                                          September 1981
RFC 792



Summary of Message Types

    0  Echo Reply

    3  Destination Unreachable

    4  Source Quench

    5  Redirect

    8  Echo

   11  Time Exceeded

   12  Parameter Problem

   13  Timestamp

   14  Timestamp Reply

   15  Information Request

   16  Information Reply



























[Page 20]                                                               

September 1981                                                          
RFC 792



References

   [1]  Postel, J. (ed.), "Internet Protocol - DARPA Internet Program
         Protocol Specification," RFC 791, USC/Information Sciences
         Institute, September 1981.

   [2]   Cerf, V., "The Catenet Model for Internetworking," IEN 48,
         Information Processing Techniques Office, Defense Advanced
         Research Projects Agency, July 1978.

   [3]   Strazisar, V., "Gateway Routing:  An Implementation
         Specification", IEN 30, Bolt Beranek and Newman, April 1979.

   [4]   Strazisar, V., "How to Build a Gateway", IEN 109, Bolt Beranek
         and Newman, August 1979.

   [5]   Mills, D., "DCNET Internet Clock Service," RFC 778, COMSAT
         Laboratories, April 1981.

   






























                                                               [Page 21]

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=head1 RELATED MODULES

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut
