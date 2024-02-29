#! c:\perl\bin\perl.exe
#---------------------------------------------------------------------
# pcaparse.pl - Script to parse Win11 PCA files
# Parse Win11 PCA files
#
# History
#  20240226 - created
#
# WinXP Path:
#  C:\Documents and Settings\user\Application Data\Sun\Java\Deployment\cache\6.0
#
# Win7 Path:
#  C:\Users\user\AppData\LocalLow\Sun\Java\Deployment\cache\6.0
#
# copyright 2024 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#---------------------------------------------------------------------
use strict;
use Time::Local;
use Getopt::Long;

my $VERSION = 20240226;

my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(file|f=s help|?|h));

if ($config{help} || ! %config) {
	_syntax();
	exit 1;
}

my $file = $config{file};
open(FH,"<",$file) || die "Could not open $file: $!\n";
while(<FH>) {
	my $line = $_;
	chomp($line);
	my @items = split(/\|/,$line);
	my $n = scalar @items;
# Win11 pcaapplaunchdic.txt	
	if ($n == 2) {
		my $path = $items[0];
		my $date = $items[1];
		my $t = parseDateField($date);
		print $t."|PCA|||".$path."\n";
	}
# Win11 pcageneraldb0.txt	
	elsif ($n == 8) {
		my $date = $items[0];
		my $t = parseDateField($date);
		$items[2] =~ s/\00//g;
		$items[7] =~ s/\00//g;
		print $t."|PCA|||".$items[2]." - ".$items[7]."\n";
	}
	else {
#		print "Total elements: ".$n." - unknown number of elements\n";
	}
}
close(FH);

#----------------------------------------------------------
# parseDateField()
# Takes the "date:" field from the server response (if there is one)
# and returns a Unix epoch time
#----------------------------------------------------------
sub parseDateField {
	my $date = shift;
	
	my ($d,$t) = split(/\s/,$date,2);
	
	$d =~ s/\00//g;
	$t =~ s/\00//g;
	
	my ($year,$month,$day) = split(/-/,$d,3);
	my ($hour,$min,$s) = split(/:/,$t,3);
	my $sec = (split(/\./,$s))[0];
	return timegm($sec,$min,$hour,$day,($month - 1),$year);
}

sub _syntax {
print<< "EOT";
pcaparse v\.$VERSION [option]
Parse Win11 PCA files

  -f file........Path to a file; output in TLN format                    
  -h ............Help (print this information)
  
Ex: C:\\>pcaparse -f pcaapplaunchdic\.txt
    C:\\>pcaparse -f pcageneraldb0\.txt

**All times printed as GMT/UTC

Ref: https://aboutdfir.com/new-windows-11-pro-22h2-evidence-of-execution-artifact/
Ref: https://www.sygnia.co/blog/new-windows-11-pca-artifact/

copyright 2024 Quantum Analytics Research, LLC
EOT
}