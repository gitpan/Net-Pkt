use ExtUtils::MakeMaker;

WriteMakefile (
   NAME          => 'Net::Pkt',
   VERSION_FROM  => 'Pkt.pm',
   PREREQ_PM     => {
      Net::Ifconfig::Wrapper => 0,
      Net::Pcap              => 0.04,
   },
   ABSTRACT_FROM => 'Pkt.pm',
   AUTHOR        => 'GomoR <Net-Pkt@gomor.org>',
   LIBS          => ['-lpcap'],    # e.g., '-lm'
   DEFINE        => '',            # e.g., '-DHAVE_SOMETHING'
   INC           => '-I.',         # e.g., '-I. -I/usr/include/other'
   OBJECT        => '$(O_FILES)',  # link all the C files too
);
