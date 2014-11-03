#! C:\perl\bin\perl.exe
#-----------------------------------------------------------
# Parse the output of the following LogParser command:
#
# logparser -i:evt -o:csv "SELECT RecordNumber, TO_UTCTIME(TimeGenerated),
#   EventID,SourceName,Strings from System" > system.txt
#
# History:
#   20141103 - updated to parse LogParser output lines with multiple 
#              carriage returns
#
#
# copyright 2014 QAR, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
use strict;
use Time::Local;

my $file = shift || die "You must enter a file name.\n";

#Read in eventmap.txt file
my %evts = ();
my ($tag1,$prec);
my $mapfile = "eventmap\.txt";
if (-e $mapfile) {
	open(FH,"<",$mapfile);
	while(<FH>) {
		chomp;
# skip comments/blank lines
		next if ($_ =~ m/^#/ || $_ =~ /^\s*$/);
		($tag1,$prec) = split(/:/,$_,2);
		$evts{$tag1} = $prec;
	}
	close(FH);
}

my @lines = ();
my $l = "";

open(FH,"<",$file) || die "Could not open $file: $!\n";
while(<FH>) {
	chomp;
	if ($_ =~ m/^\d+\,\d+/) {
		$l = join('|',@lines);
		processLogLine($l);
		@lines = ();
		push(@lines,$_);
	}
	else {		
		push(@lines,$_);
	}
}
close(FH);

sub processLogLine {
	my @data = shift;
	my $line = "";
	
	if (scalar(@data) >= 1 && $data[0] =~ m/^\d+,\d+/) {
		$line = join('|',@data);
		my ($num,$date,$id,$source,$strings) = split(/,/,$line,5);
		my $epoch = getEpoch($date);		
		$strings =~ s/\|/,/g;
		my $descr;
		if (exists $evts{$source."/".$id}) {
			$descr = $evts{$source."/".$id}." ".$source."/".$id.";".$strings;
		}
		else {
			$descr = $source."/".$id.";".$strings;
		}
		print $epoch."|EVTX|Server||".$descr."\n";
	}
}

sub getEpoch($) {
	my $date = shift;
	my($d,$t) = split(/\s/,$date,2);
	my($hr,$min,$sec) = split(/:/,$t,3);
	my($year,$mon,$mday) = split(/-/,$d,3);
	
	my $epoch = timegm($sec,$min,$hr,$mday,($mon - 1),$year);
	return $epoch;
}