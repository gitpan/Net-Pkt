package Net::Pkt::Dump;

# $Date: 2004/08/29 19:16:01 $
# $Revision: 1.37.2.1 $

use strict;
use warnings;
use Carp;

require Net::Pkt;
our @ISA = qw(Net::Pkt);

use Net::Pkt::Frame;
use Net::Pcap;

CHECK {
   croak("@{[(caller(0))[3]]}: $Net::Pkt::Tcpdump: file not found ; ".
         "you must set the path to tcpdump using \$Net::Pkt::Tcpdump")
      unless -f $Net::Pkt::Tcpdump;
}

our @AccessorsScalar = qw(
   file
   unlinkAfterAnalyze  
   filter
   overwrite
   pid
   waitOnStop
   _pcapd
);
our @AccessorsArray = qw(
   frames
);

sub new {
   my $self = shift->SUPER::new(
      file       => "netpkt-tmp-$$.@{[int rand 0xffffffff]}.pcap",
      waitOnStop => 3,
      @_,
   );

   return $self;
}

sub start {
   my $self = shift;

   if ($self->file && -f $self->file
   && ! $self->overwrite) {
      $self->debugPrint("`overwrite' parameter is undef, and file exists, ".
                        "we will only analyze it.");

      return $Net::Pkt::Dump = $self;
   }
   else {
      croak("@{[(caller(0))[3]]}: \$Net::Pkt::Dev variable not set")
         unless $Net::Pkt::Dev;

      my $child = fork;
      croak("@{[(caller(0))[3]]}: fork: $!") unless defined $child;

      if ($child) {
         sleep 1; # Give time to forked process to exec() correctly
         $self->pid($child);
         $SIG{CHLD} = 'IGNORE';
         return $Net::Pkt::Dump = $self;
      }
      else {
         $self->debugPrint("Tcpdump: [$Net::Pkt::Tcpdump]\n".
                           "Dev:     [@{[$Net::Pkt::Dev]}]\n".
                           "file:    [@{[$self->file]}]\n".
                           "filter:  [@{[$self->filter]}]");

         close STDERR unless $Net::Pkt::Debug && $Net::Pkt::Debug >= 2;

         exec($Net::Pkt::Tcpdump, '-p', '-i', $Net::Pkt::Dev, '-s', 1514,
            '-w', $self->file, $self->filter)
               or croak("@{[(caller(0))[3]]}: exec: tcpdump: $!");
      }
   }
}

sub stop {
   my $self = shift;

   if ($self->pid) {
      sleep $self->waitOnStop if $self->waitOnStop;

      kill('TERM', $self->pid);
      $self->pid(undef);
      sleep 1; # Give time to forked process to be kill()ed correctly
   }
}

sub _loopAnalyze {
   my ($userData, $hdr, $pkt) = @_;

   my $frame = Net::Pkt::Frame->new(raw => $pkt);
   defined $frame
      ? push @$userData, $frame
      : carp("@{[(caller(0))[3]]}: unknown frame (number ",
             scalar @$userData, ")");
}

sub analyze {
   my $self = shift;

   croak("@{[(caller(0))[3]]}: @{[$self->file]}: file not found")
      unless $self->file && -f $self->file;

   my $err;
   $self->_pcapd(Net::Pcap::open_offline($self->file, \$err));
   unless ($self->_pcapd) {
      carp("@{[(caller(0))[3]]}: Net::Pcap::open_offline: $err");
      return undef;
   }

   my @frames;
   Net::Pcap::loop($self->_pcapd, -1, \&_loopAnalyze, \@frames);
   $self->frames(\@frames);

   Net::Pcap::close($self->_pcapd);
   $self->_pcapd(undef);

   unlink $self->file if $self->unlinkAfterAnalyze;
}

sub DESTROY {
   my $self = shift;

   $self->stop;
   kill('TERM', $self->pid) if $self->pid;
   $self->SUPER::DESTROY if $self->can("SUPER::DESTROY");
}

#
# Accessors
#

for my $a (@AccessorsScalar) {
   no strict 'refs';
   *$a = sub { shift->_AccessorScalar($a, @_) }
}
for my $a (@AccessorsArray) {
   no strict 'refs';
   *$a = sub { shift->_AccessorArray($a, @_) }
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
