package Net::Pkt::Layer4;

# $Date: 2004/09/02 16:21:10 $
# $Revision: 1.3.2.1 $

require Net::Pkt::Layer;
our @ISA = qw(Net::Pkt::Layer);

sub layer { Net::Pkt::Frame::NETPKT_L_4() }

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
