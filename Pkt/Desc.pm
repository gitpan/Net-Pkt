package Net::Pkt::Desc;

# $Date: 2004/09/02 16:21:10 $
# $Revision: 1.31.2.2 $

use strict;
use warnings;
use Carp;

require Net::Pkt;
our @ISA = qw(Net::Pkt);

our @AccessorsScalar = qw(
   ipDst
   port
   transport
   _Io
   _Sockaddr
);

sub new {
   my $invocant = shift;
   my $class = ref($invocant) || $invocant;

   $class->checkParams(
      { @_ },
      [ __PACKAGE__->getAccessors ],
   ) or croak($Net::Pkt::Err);

   my $self = { @_ };
   bless($self, $class);

   Net::Pkt->autoDev unless $Net::Pkt::Dev;
   Net::Pkt->autoIp  unless $Net::Pkt::Ip;
   Net::Pkt->autoMac unless $Net::Pkt::Mac;

   $class->debugPrint("Dev: [$Net::Pkt::Dev]\n".
                      "Ip:  [$Net::Pkt::Ip]\n".
                      "Mac: [$Net::Pkt::Mac]");

   return $Net::Pkt::Desc = $self;
}

sub send {
   my ($self, $raw) = @_;

   send($self->_Io, $raw, 0, $self->_Sockaddr)
      or carp("@{[(caller(0))[3]]}: $!");
}

sub close { shift->_Io->close }

sub DESTROY {
   my $self = shift;

   do { $self->_Io->close; $self->_Io(undef); } if $self->_Io;
   $self->SUPER::DESTROY if $self->can("SUPER::DESTROY");
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

=head1 COPYRIGHT AND LICENSE
   
Copyright (c) 2004, Patrice E<lt>GomoRE<gt> Auffret
   
You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=head1 RELATED MODULES
   
L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>
   
=cut
