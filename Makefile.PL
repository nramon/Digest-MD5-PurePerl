use ExtUtils::MakeMaker;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence                                                                                                     
# the contents of the Makefile that is written.
WriteMakefile(
	'NAME' => 'Digest::MD5::PurePerl',
	'AUTHOR' => 'Ramon Novoa <ramonnovoa@gmail.com>',
	'VERSION_FROM'=>'lib/Digest/MD5/PurePerl.pm', # finds $VERSION
);
