#! c:\perl\bin\perl.exe
#----------------------------------------------------------------
# oledmp.pl
# 
# History
#
#
# References
#  OLE PropertySet structures: https://msdn.microsoft.com/en-us/library/dd942421.aspx
#  SummaryInformation structure: https://msdn.microsoft.com/en-us/library/dd942545.aspx
#
#
# copyright 2016 QAR, LLC 
# Author: H. Carvey, keydet89@yahoo.com
#----------------------------------------------------------------

use strict;
use OLE::Storage;
use OLE::Storage::Std;
use OLE::PropertySet;
use Startup;
use Getopt::Long;

my ($doc,$startup,$var);
my $version = 20160907;

my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(list|l file|f=s list_trash|lT dump_trash|dT prop|p=i dump|d=i raw|r=i help|?|h));

if ($config{help} || ! %config) {
	\_syntax();
	exit 1;
}

my $file = $config{file} || die "You must enter a filename.\n";
die "$file not found.\n" unless (-e $file);

# Some global stuff
my %ole = ();
$var = OLE::Storage->NewVar();
$startup = new Startup;
$doc = OLE::Storage->open($startup,$var,$file);

if ($config{list}) {
	eval {
		my $n = $doc->name(0)->string();
		my $d = $doc->date(0)->string();
		my $clsid = $doc->clsid(0)->string();
		print $n."  Date: ".$d."  CLSID: ".$clsid."\n";
	};
}

listOLE() if ($config{list});

do_directory(0,"") if ($config{dump});
do_directory(0,"") if ($config{raw});
do_directory(0,"") if ($config{prop});
list_trash() if ($config{list_trash});
list_trash() if ($config{dump_trash});

sub listOLE {
	do_directory(0,"");
	
	foreach my $i (sort {$a <=> $b} keys %ole) {
		my ($str1,$str2,$str3,$size,$date);
		($ole{$i}{dir} == 1) ? ($str1 = "D") : ($str1 = "F");
		($ole{$i}{macro} == 1) ? ($str2 = "M") : ($str2 = ".");
		(exists $ole{$i}{type} && $ole{$i}{type} != 0) ? ($str3 = "T") : ($str3 = ".");
		(exists $ole{$i}{size}) ? ($size = $ole{$i}{size}) : ($size = "");
		(exists $ole{$i}{date}) ? ($date = $ole{$i}{date}) : ($date = "");
		printf "%5d %3s %7d %20s %s\n",$i,($str1.$str2.$str3),$size,$date,$ole{$i}{path};
	}
}

sub do_directory {
	my ($directory_pps) = shift;
	my ($root) = shift;
	my (@pps,$pps); 
	
	my %names;
#	if ($doc->directory($directory_pps,\%names,"string")) {
#		@pps = keys %names;
#	}
	@pps = $doc->dirhandles($directory_pps);
	foreach $pps (sort {$a <=> $b} @pps) {
		$ole{$pps}{name} = $doc->name($pps)->string();
		$ole{$pps}{path} = $root."\\".$ole{$pps}{name};
	 	 
	 	eval { 
	 		$ole{$pps}{type} = OLE::PropertySet->type($doc,$pps);
	 	};
	 	
		if ($doc->is_file($pps)) {
			$ole{$pps}{dir} = 0;
# handle dumping the buffer		
			my $buf = "";
			if ($doc->read($pps,\$buf)) {
				if ($config{dump} && $pps == $config{dump}) {
					probe($buf);
				}
				
				if ($config{raw} && $pps == $config{raw}) {
					print $buf."\n";
				}
			}
			
			$ole{$pps}{size} = length($buf);
# Method for locating macros in a stream borrowed from:
# http://www.decalage.info/vba_tools			
			my $mac = "\00Attribut";
			if (grep(/$mac/,$buf)) {
				$ole{$pps}{macro} = 1;
			}
			else {
				$ole{$pps}{macro} = 0;
			}
# Handle getting properties (if avail)
			if ($config{prop} && $pps == $config{prop} && $ole{$pps}{type} != 0) {
				if ($ole{$pps}{name} eq "\05SummaryInformation") {
					if (my $prop = OLE::PropertySet->load($startup,$var,$pps,$doc)) {
						my ($title,$subject,$authress,$lastauth,$revnum,$appname,
				 		$created,$lastsaved,$lastprinted) =
				 		string {$prop->property(2,3,4,8,9,18,12,13,11)};
				 		print "-" x 20,"\n";
				 		print "Summary Information\n";
				 		print "-" x 20,"\n";
				 		print "Title        : $title\n";
				 		print "Subject      : $subject\n";
				 		print "Authress     : $authress\n";
				 		print "LastAuth     : $lastauth\n";
				 		print "RevNum       : $revnum\n";
				 		print "AppName      : $appname\n";
				 		print "Created      : $created\n";
				 		print "Last Saved   : $lastsaved\n";
				 		print "Last Printed : $lastprinted\n";
				 		print "\n";
					}
				}
				elsif ($ole{$pps}{name} eq "\05DocumentSummaryInformation") {
					if (my $prop = OLE::PropertySet->load($startup,$var,$pps,$doc)) {
						my $org = string {$prop->property(15)};
						print "-" x 20,"\n";
						print "Document Summary Information\n";
						print "-" x 20,"\n";
						print "Organization : $org\n";
						print "\n";
					}
				}
				else {}
			}			
		}
		elsif ($doc->is_directory($pps)) {
			$ole{$pps}{dir} = 1;

			eval {
				$ole{$pps}{name} = $doc->name($pps)->string();
				$ole{$pps}{date} = $doc->date($pps)->string();
			};

			\do_directory($pps,$ole{$pps}{path});
		}
		else {
# yeah, no...			
		}
	}
}



# Trash described here: http://search.cpan.org/~mschwartz/OLE-Storage-0.386/Storage.pm
sub list_trash {
	# Trash Sections
	my @type = ("Big blocks", "Small blocks", "File space", "System space");
	my @l = 0;
	my $buf = "";
  
	for (my $i=0; $i<=3; $i++) {
		$l[$i] = $doc->size_trash(2**$i);
		printf ("Type %d %15s %5d bytes\n", 2**$i, "(".$type[$i]."):", $l[$i]);
		
		if ($config{dump_trash}) {
			print "\n" if ($l[$i] > 0);
			if (1 == $doc->read_trash(2**$i, \$buf)) {
				probe($buf);
			}
			print "\n" if ($l[$i] > 0);
		}
	}
}


sub _syntax {
	print<< "EOT";
oledmp v.$version [-f file][options]
Access contents of OLE structured storage files
 
  -f file......file to parse
  -l...........list streams
  -d num.......(hex) dump of stream
  -r num.......raw dump of stream 
  -p num.......get properties of stream 
  -lT..........list Trash table contents
  -dT..........(hex) dump Trash table contents             
  -h...........Help (print this information)

Ex: C:\\>oledmp -f test\.pub -l 
    C:\\>oledmp -f test\.pub -p 17

copyright 2016 Quantum Analytics Research, LLC
EOT
}



#-----------------------------------------------------------
# probe()
#
# Code the uses printData() to insert a 'probe' into a specific
# location and display the data
#
# Input: binary data of arbitrary length
# Output: Nothing, no return value.  Displays data to the console
#-----------------------------------------------------------
sub probe {
	my $data = shift;
	my @d = printData($data);
	
	foreach (0..(scalar(@d) - 1)) {
		print $d[$_]."\n";
	}
}

#-----------------------------------------------------------
# printData()
# subroutine used primarily for debugging; takes an arbitrary
# length of binary data, prints it out in hex editor-style
# format for easy debugging
#-----------------------------------------------------------
sub printData {
	my $data = shift;
	my $len = length($data);
	
	my @display = ();
	
	my $loop = $len/16;
	$loop++ if ($len%16);
	
	foreach my $cnt (0..($loop - 1)) {
# How much is left?
		my $left = $len - ($cnt * 16);
		
		my $n;
		($left < 16) ? ($n = $left) : ($n = 16);

		my $seg = substr($data,$cnt * 16,$n);
		my $lhs = "";
		my $rhs = "";
		foreach my $i ($seg =~ m/./gs) {
# This loop is to process each character at a time.
			$lhs .= sprintf(" %02X",ord($i));
			if ($i =~ m/[ -~]/) {
				$rhs .= $i;
    	}
    	else {
				$rhs .= ".";
     	}
		}
		$display[$cnt] = sprintf("0x%08X  %-50s %s",$cnt,$lhs,$rhs);

	}
	return @display;
}