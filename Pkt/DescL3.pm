package Net::Pkt::DescL3;

# $Date: 2004/09/02 16:21:10 $
# $Revision: 1.10.2.2 $

use strict;
use warnings;
use Carp;

require Net::Pkt::Desc;
our @ISA = qw(Net::Pkt::Desc);

use Socket;
use IO::Socket;

use constant NETPKT_IPPROTO_RAW => 255;
use constant NETPKT_IPPROTO_IP  => 0;
use constant NETPKT_IP_HDRINCL  => 2;

sub new {
   my $self = shift->SUPER::new(@_);

   croak("@{[(caller(0))[3]]}: you must pass `ipDst' parameter")
      unless $self->ipDst;

   socket(S, AF_INET, SOCK_RAW, NETPKT_IPPROTO_RAW)
      or croak("@{[(caller(0))[3]]}: socket: $!");
   setsockopt(S, NETPKT_IPPROTO_IP, NETPKT_IP_HDRINCL, 1)
      or croak("@{[(caller(0))[3]]}: setsockopt: $!");

   my $fd = fileno(S) or croak("@{[(caller(0))[3]]}: fileno: $!");

   # XXX: maybe socket() and setsockopt() could be avoided using only IO::Socket
   my $io = IO::Socket->new;
   $io->fdopen($fd, "w") or croak("@{[(caller(0))[3]]}: fdopen: $!");
   $self->_Io($io);

   my $iaddr = gethostbyname($self->ipDst);
   my $sin = sockaddr_in(0, $iaddr);
   $self->_Sockaddr($sin);

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
