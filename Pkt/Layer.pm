package Net::Pkt::Layer;

# $Date: 2004/09/02 16:21:10 $
# $Revision: 1.22.2.1 $

use strict;
use warnings;
use Carp;

require Net::Pkt::Frame;
our @ISA = qw(Net::Pkt::Frame);

sub new {
   my $invocant = shift;
   my $class = ref($invocant) || $invocant;

   $class->checkParams(
      { @_ },
      [ $class->getAccessors, Net::Pkt::Frame->getAccessors ], 
   ) or croak($Net::Pkt::Err);

   my $self = { @_ };
   bless($self, $class);

   $self->unpack if $self->raw;

   return $self;
}

sub is {
   my $layer = ref(shift);
   $layer =~ s/^Net::Pkt::Layer//;
   return $layer;
}

sub layer { Net::Pkt::Frame::NETPKT_L_UNKNOWN() }
sub encapsulate { Net::Pkt::Frame::NETPKT_LAYER_NONE() }
sub computeLengths {}
sub computeChecksums {}
sub print {}

sub dump {
   my $self = shift;

   my $hex = unpack('H*', $self->raw);
   $hex =~ s/(..)/\\x$1/g;
   $hex =~ s/\\x$//;
   print "@{[$self->layer]}: @{[$self->is]}: \"$hex\"\n";
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
