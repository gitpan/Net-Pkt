package Net::Pkt::Quick;

# $Date: 2004/09/02 16:21:10 $
# $Revision: 1.9.2.2 $

use strict;
use warnings;
use Carp;

use Net::Pkt::LayerETH qw(/NETPKT_*/);
use Net::Pkt::LayerARP qw(/NETPKT_*/);
use Net::Pkt::LayerIPv4 qw(/NETPKT_*/);
use Net::Pkt::LayerTCP qw(/NETPKT_*/);
use Net::Pkt::Layer7 qw(/NETPKT_*/);
use Net::Pkt::Frame;

sub tcpSyn {
   my $self = shift;
   my $args = { @_ };

   croak("Usage:\n".
         "my \$frame = @{[(caller(0))[3]]}(\n".
         " [ ipSrc   => IP, ]\n".
         "   ipDst   => IP,\n".
         "   dstPort => PORT,\n".
         ");\n".
         "")
      unless $args->{ipDst}
          && $args->{dstPort}
   ;

   my $ip = Net::Pkt::LayerIPv4->new(
      src => $args->{ipSrc},
      dst => $args->{ipDst},
   );

   my $tcp = Net::Pkt::LayerTCP->new(
      dst   => $args->{dstPort},
      flags => NETPKT_TCP_FLAG_SYN,
   );

   Net::Pkt::Frame->new(l3 => $ip, l4 => $tcp);
}

sub arpRequest {
   my $self = shift;
   my $args = {
      broadcast => undef,
      @_,
   };

   croak("Usage:\n".
         "my \$frame = @{[(caller(0))[3]]}(\n".
         "   tellMac => MAC,\n".
         "   toMac   => MAC or 'broadcast',\n".
         "   tell    => IP,\n".
         "   whoHas  => IP,\n".
         ");\n".
         "")
      unless $args->{tellMac}
          && $args->{toMac}
          && $args->{tell}
          && $args->{whoHas}
   ;

   my $eth = Net::Pkt::LayerETH->new(
      src => $args->{tellMac},
      dst => $args->{toMac} =~ /broadcast/i ? NETPKT_ETH_ADDR_BROADCAST
                                            : $args->{toMac},
      type => NETPKT_ETH_TYPE_ARP,
   );

   my $arp = Net::Pkt::LayerARP->new(   
      hType  => NETPKT_ARP_HTYPE_ETH,
      pType  => NETPKT_ARP_PTYPE_IPv4,
      hSize  => NETPKT_ARP_HSIZE_ETH,
      pSize  => NETPKT_ARP_PSIZE_IPv4,
      opCode => NETPKT_ARP_OPCODE_REQUEST,
      src    => $args->{tellMac},
      srcIp  => $args->{tell},
      dst    => $args->{toMac} =~ /broadcast/i ? NETPKT_ARP_ADDR_BROADCAST
                                               : $args->{toMac},
      dstIp => $args->{whoHas},
   );

   Net::Pkt::Frame->new(l2 => $eth, l3 => $arp);
}

sub arpReply {
   my $self = shift;
   my $args = { @_ };

   croak("Usage:\n".
         "my \$frame = @{[(caller(0))[3]]}(\n".
         "   srcMac => SRC_MAC (ETH layer),\n".
         "   isAt   => MAC,\n".
         "   toMac  => MAC or 'broadcast',\n".
         "   ip     => IP,\n".
         ");\n".
         "")
      unless $args->{srcMac}
          && $args->{isAt}
          && $args->{toMac}
          && $args->{ip}
   ;

   my $eth = Net::Pkt::LayerETH->new(
      src  => $args->{srcMac},
      dst  => $args->{toMac} =~ /broadcast/i ? NETPKT_ETH_ADDR_BROADCAST
                                             : $args->{toMac},
      type => NETPKT_ETH_TYPE_ARP,
   );

   my $arp = Net::Pkt::LayerARP->new(
      hType  => NETPKT_ARP_HTYPE_ETH,
      pType  => NETPKT_ARP_PTYPE_IPv4,
      hSize  => NETPKT_ARP_HSIZE_ETH,
      pSize  => NETPKT_ARP_PSIZE_IPv4,
      opCode => NETPKT_ARP_OPCODE_REPLY,
      src    => $args->{isAt},
      srcIp  => $args->{ip},
      dst    => $args->{toMac} =~ /broadcast/i ? NETPKT_ARP_ADDR_BROADCAST
                                               : $args->{toMac},
      dstIp  => $args->{ip},
   );

   Net::Pkt::Frame->new(l2 => $eth, l3 => $arp);
}

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
