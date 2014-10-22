#! c:\perl\bin\perl.exe
#-------------------------------------------------------------
# ftkparse.pl
# Parse the .csv output from FTK Imager's "Export Directory Listing..."
# to TSK bodyfile format
#
# TSK fls.exe 3.x output:
#    MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
#
# Puts a 0 into the ctime field (that's defined in the TSK format as the 
# 'entry modified' time; crtime is file creation time)
#
# Change History:
#   20110523 - date module changed to Time::Local
#
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-------------------------------------------------------------
use strict;
use Time::Local;

my $file = shift || die "You must enter a filename.\n";
die $file." not found.\n" unless (-e $file && -f $file);

my %months = (
	Jan => 1,
	Feb => 2,
	Mar => 3,
	Apr => 4,
	May => 5,
	Jun => 6,
	Jul => 7,
	Aug => 8,
	Sep => 9,
	Oct => 10,
	Nov => 11,
	Dec => 12 );

my $noname = "NONAME \\x5BNTFS\\x5D";
open(FH,"<",$file) || die "Could not open ".$file.": $!\n";
while(<FH>) {
	chomp;
	$_ =~ s/\00//g;
	my ($filename,$path,$size,$c_time,$m_time,$a_time,$del) = split(/\t/,$_,7);
	next if ($path eq "Full Path");
	$path =~ s/^$noname//;

	next if ($c_time eq "" || $m_time eq "" || $a_time eq "");
	my $ctime = dateToEpoch($c_time);
	my $mtime = dateToEpoch($m_time);
	my $atime = dateToEpoch($a_time); 
	print "0|".$path."|||||".$size."|".$atime."|".$mtime."|0|".$ctime."\n";
}
close(FH);

sub dateToEpoch {
	my $input = shift;
	my $epoch;
	eval {
		my ($date,$time) = (split(/\s/,$input,3))[0,1];
		my ($yy,$mm,$dd) = split(/-/,$date,3);
		my ($hr,$min,$ss) = split(/:/,$time,3);
		my $sec = (split(/\./,$ss,2))[0];
#		$dt = DateTime->new(year => $yy, month => $months{$mm}, day => $dd, 
#                       hour => $hr, minute => $min, second => $sec);
#		return $dt->epoch;
		$epoch = timegm($sec,$min,$hr,$dd,($months{$mm} - 1),$yy);
	};
	if ($@) {
		print "Error -> ".$input.": ".$@."\n";
		return 0;
	}
	else {
		return $epoch;
	}
}