package Net::Pkt::Layer2;

# $Date: 2004/08/29 18:11:32 $
# $Revision: 1.3 $

require Net::Pkt::Layer;
our @ISA = qw(Net::Pkt::Layer);

sub layer { Net::Pkt::Frame::NETPKT_L_2() }

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
