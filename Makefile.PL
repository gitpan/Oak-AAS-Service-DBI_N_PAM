use ExtUtils::MakeMaker;

my $mm = new MM
 (
  {
   AUTHOR => "Daniel Ruoso <daniel\@ruoso.com>",
   ABSTRACT => "Perl Oak Component Tree",
   NAME => "Oak::AAS::Service::DBI_N_PAM",
   VERSION => "1.8",
   PREREQ_PM => 
   {
    'Authen::PAM'   => '0',
    'Oak::AAS::Service' => '0',
    'Oak::IO::DBI' => '0',
   }
  }
 );

$mm->flush;
