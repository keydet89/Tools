#!c:\perl\bin\perl.exe 
#------------------------------------------------------------
# rlo - tool to traverse a hive file, checking for the use of the
#       Unicode RLO control char in key/value names
#
# Change History
#   20130826 - created
#
# Reference:
#   http://blogs.technet.com/b/mmpc/archive/2013/08/19/reversal-of-fortune-sirefef-s-registry-illusion.aspx
#
# copyright 2013 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#------------------------------------------------------------
use strict;
use Parse::Win32Registry qw(:REG_);

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

my $hive = shift;

if ($hive eq "") {
	\usage();
	exit 1;
}

my %regkeys;
my $reg = Parse::Win32Registry->new($hive);
my $root_key = $reg->get_root_key;
my $root = $root_key->as_string();
$root = (split(/\[/,$root))[0];
chop($root);

traverse($root_key,$root);

sub traverse {
	my $key = shift;
	my $mask = shift;
  my $ts = $key->get_timestamp();
  my $path = $key->as_string();

  $path = (split(/\[/,$path))[0];
	$path =~ s/$mask//;
#	print $path."\n";
	
  my $name = $key->get_name();
  if (checkRLO($name) == 1) {
  	my $n = convertRLOName($name);
  	$path =~ s/$name/$n/;
  	print "RLO control char detected in key name: ".$path."\n";
  }
  
  foreach my $val ($key->get_list_of_values()) {
  	my $val_name = $val->get_name();
  	if (checkRLO($val_name) == 1) {
  		my $n = convertRLOName($val_name);
  		print "RLO control char detected in value name: ".$path.":".$n."\n";
  	}
  }
    
	foreach my $subkey ($key->get_list_of_subkeys()) {
		traverse($subkey,$mask);
  }
}

sub usage {
    print << "USAGE";
rlo <hive> 
Traverse through a Registry hive file, looking for key and value names
that include the Unicode RLO control character.

copyright 2013 Quantum Analytics Research, LLC    
USAGE
}

sub checkRLO {
	my $name = shift;
	
	my @name_list = split(//,$name);
	my ($hex,@hex_list);
	my $rlo = 0;
	$hex = unpack("H*",$name);
			
	for (my $i = 0; $i < length $hex; $i+=2) {
		push(@hex_list, substr($hex,$i,2));
	}
		
	if (scalar(@name_list) == scalar(@hex_list)) {
		foreach my $i (0..(scalar(@name_list) - 1)) {
			$rlo = 1 if (($hex_list[$i] eq "2e") && ($name_list[$i] ne "\.")); 
		}
	}
	else {
		return undef;
	}
	return $rlo;
}

sub convertRLOName {
	my $name = shift;
	my @name_list = split(//,$name);
	
	my ($hex,@hex_list);
	$hex = unpack("H*",$name);
	for (my $i = 0; $i < length $hex; $i+=2) {
		push(@hex_list, substr($hex,$i,2));
	}
	
	foreach my $i (0..(scalar(@name_list) - 1)) {
		if ($hex_list[$i] eq "2e") {
			$name_list[$i] = "\.";
		}
	}
	return join('',@name_list);
}
