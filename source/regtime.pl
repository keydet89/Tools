#!c:\perl\bin\perl.exe 
#------------------------------------------------------------
# RegTime - tool to traverse a hive file and output the key
#           LastWrites and names in TLN format
#
# Change History
#   20120515 - updated with Parse::Win32Registry v1.0 pragmas, so that the
#              tool can be compiled with Perl2Exe
#   20110509 - updated to TLN output
#
#
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#------------------------------------------------------------
use strict;
use Parse::Win32Registry qw(:REG_);
use Getopt::Long;
# Included to permit compiling via Perl2Exe
#perl2exe_include "Parse/Win32Registry.pm";
#perl2exe_include "Parse/Win32Registry/Key.pm";
#perl2exe_include "Parse/Win32Registry/Entry.pm";
#perl2exe_include "Parse/Win32Registry/Value.pm";
#perl2exe_include "Parse/Win32Registry/File.pm";
#perl2exe_include "Parse/Win32Registry/Win95/File.pm";
#perl2exe_include "Parse/Win32Registry/Win95/Key.pm";
#perl2exe_include "Encode.pm";
#perl2exe_include "Encode/Byte.pm";
#perl2exe_include "Encode/Unicode.pm";
#perl2exe_include "utf8.pm";
#perl2exe_include "unicore/Heavy.pl";
#perl2exe_include "unicore/To/Upper.pl";
my $VERSION = "1\.0\.20120515";

my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(m=s reg|r=s server|s=s user|u=s help|?|h));

if ($config{help} || !%config || !$config{reg}) {
	\usage();
	exit 0;
}

$config{m} = "\./" unless $config{m};
$config{m} =~ s/\\/\//g;
#$config{m} = $config{m}."/" unless ($config{m} =~ m/\/$/);
die $config{reg}." not found.\n" unless (-e $config{reg});

$config{user} = "" unless $config{user};


my %regkeys;
my $reg = Parse::Win32Registry->new($config{reg});
my $root_key = $reg->get_root_key;

traverse($root_key);

foreach my $t (reverse sort {$a <=> $b} keys %regkeys) {
	foreach my $item (@{$regkeys{$t}}) {
		$item =~ s/\\/\//g;
		print $t."|REG|".$config{server}."|".$config{user}."|M... ".$config{m}."$item\n";
	}
}

sub traverse {
	my $key = shift;
  my $ts = $key->get_timestamp();
  my $name = $key->as_string();
  $name =~ s/\$\$\$PROTO\.HIV//;
  $name = (split(/\[/,$name))[0];
  push(@{$regkeys{$ts}},$name);  
	foreach my $subkey ($key->get_list_of_subkeys()) {
		traverse($subkey);
  }
}

sub usage {
    print << "USAGE";
regtime v. $VERSION 
Traverse through a Registry hive file, listing all keys and their LastWrite
times.  Output is displayed sorted by most recent time first, and is suitable
for use with TSK v3.0 fls and mactime

  -m hive.........Hive file to prepend to key paths (use / separator, use _ 
                  or enclose in quotes if spaces in path)
  -r hive.........Hive file to parse
  -s name.........System name
  -u name.........User name
  -h..............Help (print this information)
  
Ex: C:\>regtime -m HKEY_USER/ -r NTUSER.DAT
    C:\>regtime -m HKLM/System/ -r system    
    
copyright 2012 Quantum Analytics Research, LLC    
USAGE
}
  
