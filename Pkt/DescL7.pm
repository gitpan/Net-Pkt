package Net::Pkt::DescL7;

# $Date: 2004/09/02 16:21:10 $
# $Revision: 1.9.2.2 $

use strict;
use warnings;
use Carp;

require Net::Pkt::Desc;
our @ISA = qw(Net::Pkt::Desc);

use Socket;
use IO::Socket;
use IO::Select;

sub new {
   my $self = shift->SUPER::new(@_);

   croak("Usage:\n".
         "my \$desc = @{[(caller(0))[3]]}(\n".
         "   ipDst => IP,\n".
         "   port => IP,\n".
         "   transport => TCP or UDP,\n".
         ");")
      unless $self->ipDst && $self->port && $self->transport;

   my $iaddr = gethostbyname($self->ipDst);
   my $sin = sockaddr_in($self->port, $iaddr);
   $self->_Sockaddr($sin);

   # XXX: maybe socket() and connect() could be avoided using only IO::Socket
   if ($self->transport =~ /tcp/i) {
      socket(S, AF_INET, SOCK_STREAM, 0)
         or croak("@{[(caller(0))[3]]}: socket: SOCK_STREAM: $!");

      connect(S, $sin) or croak("@{[(caller(0))[3]]}: connect: TCP: $!");
   }
   else {
      socket(S, AF_INET, SOCK_DGRAM, 0)
         or croak("@{[(caller(0))[3]]}: socket: SOCK_DGRAM: $!");
   }

   my $io = IO::Socket->new_from_fd(fileno(S), "r+")
      or croak("@{[(caller(0))[3]]}: IO::Socket->new_from_fd: $!");
   $self->_Io($io);

   return $self;
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
