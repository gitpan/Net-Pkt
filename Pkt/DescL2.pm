package Net::Pkt::DescL2;

# $Date: 2004/08/29 19:10:21 $
# $Revision: 1.11.2.1 $

use strict;
use warnings;
use Carp;

require Net::Pkt::Desc;
our @ISA = qw(Net::Pkt::Desc);

use Socket;
use IO::Socket;

BEGIN {
   my $osname = {
      linux => '_sendLinux',
   };

   *send = \&{$osname->{$^O} || '_sendOther'};
}

sub new {
   my $self = shift->SUPER::new(@_);

   croak("@{[(caller(0))[3]]}: \$Net::Pkt::Dev variable not set")
      unless $Net::Pkt::Dev;

   my $fd = Net::Pkt::netpkt_open_l2($Net::Pkt::Dev)
      or croak("@{[(caller(0))[3]]}: netpkt_open_l2: $Net::Pkt::Dev: $!");

   my $io = IO::Socket->new;
   $io->fdopen($fd, "w") or croak("@{[(caller(0))[3]]}: fdopen: $!");
   $self->_Io($io);

   return $self;
}

sub _sendLinux {
   my ($self, $raw) = @_;

   # Here is the Linux dirty hack (to choose outgoing device, surely)
   my $sin = pack('S a14', 0, $Net::Pkt::Dev);
   CORE::send($self->_Io, $raw, 0, $sin)
      or croak("@{[(caller(0))[3]]}: send: $!");
}

sub _sendOther {
   my ($self, $raw) = @_;

   $self->_Io->syswrite($raw, length $raw)
      or croak("@{[(caller(0))[3]]}: syswrite: $!");
}

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
