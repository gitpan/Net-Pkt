use ExtUtils::MakeMaker;

WriteMakefile (
   'NAME' => 'Net::Pkt',
   'VERSION_FROM' => 'Pkt.pm',
   'PREREQ_PM' => {}, # e.g., Module::Name => 1.1
   (
      $] >= 5.005    ## Add these new keywords supported since 5.005
         ? (
            ABSTRACT_FROM => 'Pkt.pm',
            AUTHOR => 'GomoR <Net-Pkt@gomor.org>',
         )
         : (),
   ),
   'LIBS' => [''], # e.g., '-lm'
   'DEFINE' => '', # e.g., '-DHAVE_SOMETHING'
   'INC' => '-I.', # e.g., '-I. -I/usr/include/other'
   'OBJECT' => '$(O_FILES)', # link all the C files too
);
