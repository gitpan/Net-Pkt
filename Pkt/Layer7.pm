package Net::Pkt::Layer7;

# $Date: 2004/09/02 16:21:10 $
# $Revision: 1.11.2.2 $

use strict;
use warnings;
use Carp;

require Net::Pkt::Layer;
our @ISA = qw(Net::Pkt::Layer);

sub layer { Net::Pkt::Frame::NETPKT_L_7() }

our @AccessorsScalar = qw(
   data
   dataLength
);

sub new {
   my $self = shift->SUPER::new(@_);

   # Compute length only if not raw param passed, since otherwise
   # unpack will take care of if
   $self->_computeDataLength unless $self->raw;

   return $self;
}

sub pack {
   my $self = shift;

   $self->raw(pack('a*', $self->data));
   $self->rawLength(length $self->raw);
}

sub unpack {
   my $self = shift;

   $self->data(unpack('a*', $self->raw));
   $self->dataLength(length $self->data);
}

sub _computeDataLength {
   my $self = shift;
   $self->data
      ? $self->dataLength(length $self->data)
      : $self->dataLength(0);
}

sub computeLengths { shift->_computeDataLength }

sub recv {
   my ($self, $type) = @_;

   if ($type =~ /^\d+$/) {
      return $self->_recvSize($type);
   }
   elsif ($type eq 'getline') {
      return $self->_recvLine;
   }

   return undef;
}

sub _recvLine { $Net::Pkt::Desc->_Io->getline }

sub _recvSize {
   my ($self, $size) = @_;

   my $read;
   my $sel = IO::Select->new($Net::Pkt::Desc->_Io);
   while ($sel->can_read(10)) {
      my $local;

      my $ret = $Net::Pkt::Desc->_Io->sysread($local, $size);
      $read .= $local;

      if ($ret == 0) {
         carp("@{[(caller(0))[3]]}: sysread: EOF received");
         $read .= "[EOF]\n";
         last;
      }
      elsif ($ret > 0) {
         next;
      }
      else {
         carp("@{[(caller(0))[3]]}: sysread: $!");
         last;
      }
   }

   return $read;
}

sub dump {
   my $self = shift;

   my $l = $self->layer;
   my $i = $self->is;
   printf
      "$l:+$i: %s\n",
         CORE::unpack('H*', $self->data),
   ;
}

sub print {
   my $self = shift;
   print "@{[$self->layer]}:+@{[$self->is]}: @{[$self->data]}\n";
}

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
