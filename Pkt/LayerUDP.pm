package Net::Pkt::LayerUDP;

# $Date: 2004/09/20 21:25:00 $
# $Revision: 1.6.2.6 $

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
      "$l: $i: size:%d  header:%d  payload:%d\n",
         $self->checksum,
         $self->src,
         $self->dst,
         $self->len,
         NETPKT_UDP_HDR_LEN,
         $self->len - NETPKT_UDP_HDR_LEN,
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

=head1 RFC 768 - User Datagram Protocol

RFC 768                                                        J. Postel
                                                                     ISI
                                                          28 August 1980



                         User Datagram Protocol
                         ----------------------

Introduction
------------

This User Datagram  Protocol  (UDP)  is  defined  to  make  available  a
datagram   mode  of  packet-switched   computer   communication  in  the
environment  of  an  interconnected  set  of  computer  networks.   This
protocol  assumes  that the Internet  Protocol  (IP)  [1] is used as the
underlying protocol.

This protocol  provides  a procedure  for application  programs  to send
messages  to other programs  with a minimum  of protocol mechanism.  The
protocol  is transaction oriented, and delivery and duplicate protection
are not guaranteed.  Applications requiring ordered reliable delivery of
streams of data should use the Transmission Control Protocol (TCP) [2].

Format
------

                                    
                  0      7 8     15 16    23 24    31  
                 +--------+--------+--------+--------+ 
                 |     Source      |   Destination   | 
                 |      Port       |      Port       | 
                 +--------+--------+--------+--------+ 
                 |                 |                 | 
                 |     Length      |    Checksum     | 
                 +--------+--------+--------+--------+ 
                 |                                     
                 |          data octets ...            
                 +---------------- ...                 

                      User Datagram Header Format

Fields
------

Source Port is an optional field, when meaningful, it indicates the port
of the sending  process,  and may be assumed  to be the port  to which a
reply should  be addressed  in the absence of any other information.  If
not used, a value of zero is inserted.





Postel                                                          [page 1]

                                                             28 Aug 1980
User Datagram Protocol                                           RFC 768
Fields



Destination  Port has a meaning  within  the  context  of  a  particular
internet destination address.

Length  is the length  in octets  of this user datagram  including  this
header  and the data.   (This  means  the minimum value of the length is
eight.)

Checksum is the 16-bit one's complement of the one's complement sum of a
pseudo header of information from the IP header, the UDP header, and the
data,  padded  with zero octets  at the end (if  necessary)  to  make  a
multiple of two octets.

The pseudo  header  conceptually prefixed to the UDP header contains the
source  address,  the destination  address,  the protocol,  and the  UDP
length.   This information gives protection against misrouted datagrams.
This checksum procedure is the same as is used in TCP.

                  0      7 8     15 16    23 24    31 
                 +--------+--------+--------+--------+
                 |          source address           |
                 +--------+--------+--------+--------+
                 |        destination address        |
                 +--------+--------+--------+--------+
                 |  zero  |protocol|   UDP length    |
                 +--------+--------+--------+--------+

If the computed  checksum  is zero,  it is transmitted  as all ones (the
equivalent  in one's complement  arithmetic).   An all zero  transmitted
checksum  value means that the transmitter  generated  no checksum  (for
debugging or for higher level protocols that don't care).

User Interface
--------------

A user interface should allow

  the creation of new receive ports,

  receive  operations  on the receive  ports that return the data octets
  and an indication of source port and source address,

  and an operation  that allows  a datagram  to be sent,  specifying the
  data, source and destination ports and addresses to be sent.






[page 2]                                                          Postel

28 Aug 1980
RFC 768                                           User Datagram Protocol
                                                            IP Interface



IP Interface
-------------

The UDP module  must be able to determine  the  source  and  destination
internet addresses and the protocol field from the internet header.  One
possible  UDP/IP  interface  would return  the whole  internet  datagram
including all of the internet header in response to a receive operation.
Such an interface  would  also allow  the UDP to pass  a  full  internet
datagram  complete  with header  to the IP to send.  The IP would verify
certain fields for consistency and compute the internet header checksum.

Protocol Application
--------------------

The major uses of this protocol is the Internet Name Server [3], and the
Trivial File Transfer [4].

Protocol Number
---------------

This is protocol  17 (21 octal)  when used  in  the  Internet  Protocol.
Other protocol numbers are listed in [5].

References
----------

[1]     Postel,   J.,   "Internet  Protocol,"  RFC 760,  USC/Information
        Sciences Institute, January 1980.

[2]     Postel,    J.,   "Transmission   Control   Protocol,"   RFC 761,
        USC/Information Sciences Institute, January 1980.

[3]     Postel,  J.,  "Internet  Name Server,"  USC/Information Sciences
        Institute, IEN 116, August 1979.

[4]     Sollins,  K.,  "The TFTP Protocol,"  Massachusetts  Institute of
        Technology, IEN 133, January 1980.

[5]     Postel,   J.,   "Assigned   Numbers,"  USC/Information  Sciences
        Institute, RFC 762, January 1980.









Postel                                                          [page 3]

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=head1 RELATED MODULES

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut
