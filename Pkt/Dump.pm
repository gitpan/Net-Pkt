package Net::Pkt::Dump;

# $Date: 2004/09/26 19:19:12 $
# $Revision: 1.37.2.10 $

use strict;
use warnings;
use Carp;

require Net::Pkt;
our @ISA = qw(Net::Pkt);

use Net::Pkt::Frame;
use Net::Pcap;
use IO::File;
use Time::HiRes qw(gettimeofday);

BEGIN {
   $SIG{INT} = sub {
      $Net::Pkt::Dump->DESTROY;
      exit 0;
   }
}

our @AccessorsScalar = qw(
   file
   filter
   overwrite
   waitOnStop
   timeoutOnNext
   nextFrame
   callStart
   unlinkAfterAnalyze  
   noStore
   _pid
   _pcapd
   _pcapio
   _fpos
   _firstTime
);
our @AccessorsArray = qw(
   frames
);

sub new {
   my $self = shift->SUPER::new(
      file          => "netpkt-tmp-$$.@{[Net::Pkt::getRandom32bitsInt]}.pcap",
      filter        => "",
      overwrite     => 0,
      waitOnStop    => 3,
      timeoutOnNext      => 3,
      callStart          => 0,
      unlinkAfterAnalyze => 0,
      noStore            => 0,
      frames             => [],
      @_,
   );

   $Net::Pkt::Dump = $self;

   $self->start if $self->callStart;

   return $self;
}

sub start {
   my $self = shift;

   if ($self->file && -f $self->file
   && ! $self->overwrite) {
      $self->debugPrint("`overwrite' parameter is undef, and file exists, ".
                        "we will only analyze it.");
      return 1;
   }
   else {
      croak("@{[(caller(0))[3]]}: \$Net::Pkt::Dev variable not set")
         unless $Net::Pkt::Dev;

      my $child = fork;
      croak("@{[(caller(0))[3]]}: fork: $!") unless defined $child;

      if ($child) {
         # Waiting child process to create pcap file
         my $count; # Just to avoid an infinite loop and report an error
         while (! -f $self->file) { last if ++$count == 100_000_000 };
         croak("@{[(caller(0))[3]]}: too long for netpkt_tcpdump to start")
            if $count && $count == 100_000_000;

         sleep(1); # Be sure the packet capture is ready

         $self->_pid($child);
         $SIG{CHLD} = 'IGNORE';
         return 1;
      }
      else {
         $self->debugPrint("dev:    [$Net::Pkt::Dev]\n".
                           "file:   [@{[$self->file]}]\n".
                           "filter: [@{[$self->filter]}]");

         Net::Pkt::netpkt_tcpdump(
            $Net::Pkt::Dev,
            $self->file,
            $self->filter,
            1514,
            $Net::Pkt::Promisc,
         ) or croak("@{[(caller(0))[3]]}: netpkt_tcpdump: $!");
      }
   }
}

sub stop {
   my $self = shift;

   if ($self->_pid) {
      sleep $self->waitOnStop if $self->waitOnStop;

      kill('TERM', $self->_pid);
      $self->_pid(undef);
   }

   if ($self->_pcapd) {
      Net::Pcap::close($self->_pcapd);
      $self->_pcapd(undef);
      $self->_pcapio(undef);
   }
}

sub _openFile {
   my $self = shift;

   croak("@{[(caller(0))[3]]}: @{[$self->file]}: file not found")
      unless $self->file && -f $self->file;
         
   # Do not try to open if nothing is waiting
   return undef unless (stat($self->file))[7];

   my $err;
   $self->_pcapd(Net::Pcap::open_offline($self->file, \$err));
   unless ($self->_pcapd) {
      croak("@{[(caller(0))[3]]}: Net::Pcap::open_offline: @{[$self->file]}: ".
            "$err");
   }
}

sub _loopAnalyze {
   my ($userData, $hdr, $pkt) = @_;

   my $frame = Net::Pkt::Frame->new(raw => $pkt);
   defined $frame
      ? push @$userData, $frame
      : carp("@{[(caller(0))[3]]}: unknown frame (number ",
             scalar @$userData, ")\n");
}

sub analyze {
   my $self = shift;

   unless ($self->_pcapd) {
      $self->_openFile || return ();
   }

   my @frames;
   Net::Pcap::loop($self->_pcapd, -1, \&_loopAnalyze, \@frames);
   $self->frames(\@frames);

   Net::Pcap::close($self->_pcapd);
   $self->_pcapd(undef);

   unlink $self->file if $self->unlinkAfterAnalyze;

   return @frames;
}

sub _addFrame {
   my $self = shift;

   my %hdr;
   my $frame;
   if (my $raw = Net::Pcap::next($self->_pcapd, \%hdr)) {
      $frame = Net::Pkt::Frame->new(raw => $raw);
      unless ($self->noStore) {
         my @frames = $self->frames;
         push @frames, $frame;
         $self->frames(\@frames);
      }
   }

   return $frame;
}

sub next {
   my $self = shift;

   # Handle timeout
   my $thisTime = gettimeofday() if     $self->timeoutOnNext;
   $self->_firstTime($thisTime)  unless $self->_firstTime;

   if ($self->timeoutOnNext && $self->_firstTime) {
      if (($thisTime - $self->_firstTime) > $self->timeoutOnNext) {
         $Net::Pkt::Timeout = 1;
         $self->_firstTime(0);
         $self->debugPrint("Timeout occured");
         return undef;
      }
   }

   # Open the savefile and bless it to IO::File the first time method is used
   unless ($self->_pcapd) {
      $self->_openFile || return undef;
      $self->_pcapio(
         bless(Net::Pkt::netpkt_pcap_fp($self->_pcapd), 'IO::File')
      );
   }

   # If it is not the first time the function is called, we setpos
   $self->_pcapio->setpos($self->_fpos) if $self->_fpos;

   my $frame = $self->_addFrame;
   $self->_fpos($self->_pcapio->getpos);
   $self->_firstTime(0) if $frame; # Frame received, so reset timeout var

   return $self->nextFrame($frame);
}

sub DESTROY {
   my $self = shift;

   $self->waitOnStop(0);
   $self->stop;

   unlink $self->file if $self->unlinkAfterAnalyze
                      && $self->file && -f $self->file;

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

=head1 NAME

Net::Pkt::Dump - an interface for a tcpdump-like process and a frame analyzer

=head1 SYNOPSIS

   #
   # Example offline analysis
   #

   use Net::Pkt::Dump;
   my $dump = Net::Pkt::Dump->new(filter => "tcp and dst host $Net::Pkt::Ip");

   $dump->start;
   # Code sending packets
   $dump->stop;

   for ($dump->analyze) {
      # Play with what have been captured
      # See Net::Pkt::Frame for packet format
   }


   #
   # Example live analysis
   #

   use Net::Pkt::Dump;
   my $dump =  Net::Pkt::Dump->new(
      filter        => "tcp and dst host $Net::Pkt::Ip",
      timeoutOnNext => 5,
      callStart     => 1,
   );

   until ($Net::Pkt::Timeout) {
      # Code sending packets here

      if ($dump->next) {
         $dump->nextFrame->l3->print;
         # Code analyzing reply here
      }
   }

=head1 DESCRIPTION

This module provides an interface for a tcpdump-like process creator and a frame analyzer. When you call the new method, an object is returned with some default values set.

=head1 OPTIONS

=over 4

=item B<callStart> < BOOL >

If set to a true value, the start method will be called on the new object creation. The default is false.

=item B<file> < SCALAR >

This specifies in which file to store the captured frames, stored in a .pcap format file. The default is to create a randomly named file (like netpkt-tmp-PID-RANDOM32BITSINT.pcap).

=item B<unlinkAfterAnalyze> < SCALAR >

When set to 1, the file used to capture frames will be deleted after the call to analyze method (and the array frames contains the parsed frames). The default is to not remove the file after analyze.

=item B<filter> < SCALAR >

This sets the filter used to capture frames, in a pcap filter format. You can use the method Net::Pkt::Frame::getFilter to automatically set it from a Net::Pkt::Frame object. See Net::Pkt::Frame. The default is to set an empty filter, in order to capture all frames.

=item B<overwrite> < SCALAR >

When set to 1, will overwrite an existing file. If not, it will only analyze an existing one, or create a new file if it does not exist. The default is to not overwrite.

=item B<waitOnStop> < SCALAR >

When you call the stop method, you can specify a timeout before stopping the capture. The default is to sleep for 3 seconds.

=item B<noStore> < SCALAR >

When set to 1, the method next will not add the analyzed frame into the frames array, in order to avoid memory exhaustion. The default is to store frames (so to perform memory exhaustion ;) ).

=item B<timeoutOnNext> < SCALAR >

When set to a value, a timeout will occur if no new frame is received within the SCALAR value seconds. The default is 3 seconds. A 0 value means no timeout at all. If a timeout occur, the global $Net::Pkt::Dump is set to a true value.

=back

=head1 METHODS

=over 4

=item B<new> ( OPTIONS )

Create an object. The global $Net::Pkt::Dump variable will be set to the newly created object.

=item B<start>

Start packet capture, the file specified is created, unless it exists and the overwrite option is not set.

=item B<stop>

Stop packet capture.

=item B<analyze>

Parse captured packets (from a .pcap file) and return an array of Net::Pkt::Frame objects. The file is removed is the unlinkAfterAnalyze option is set.

=item B<frames>

Returns the analyzed frames as an array of Net::Pkt::Frame objects, or an empty array if none have been analyzed.

=item B<next>

Returns the next captured frame as a Net::Pkt::Frame object. Returns undef if no frame is waiting to be analyzed. By default, all new captured frames are stored into the frames array (accessed through frames method). The noStore option avoids this. If you have used the timeoutOnNext option, the global $Net::Pkt::Timeout will be set to a true value, and undef value returned. Also, when the next awaiting frame is captured, it is stored in the nextFrame object data.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=head1 RELATED MODULES

L<NetPacket>, L<Net::RawIP>, L<Net::RawSock>

=cut
