#! c:\perl\bin\perl.exe
#------------------------------------------------------------
# evtxparse.pl - Script to parse Windows Event Logs into TLN output format
#
# To use, first run the following command:
# logparser -i:evt -o:csv "Select RecordNumber,TO_UTCTIME(TimeGenerated),EventID,
#   SourceName,ComputerName,SID,Strings from <path\*.evtx>" > output.txt
#
# Then run this script against the output to parse into TLN output, and add to an
# events file.
#
# evtxparse.pl output.txt >> events.txt
#
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#------------------------------------------------------------
use strict;
use Time::Local;

my $file = shift || usage();
die "File not found.\n" unless (-e $file && -f $file);

my %ids;
my $mapfile = "eventmap\.txt";
if (-e $mapfile) {
	%ids = eventMap($mapfile);
}

open(FH,"<",$file) || die "Could not open $file: $!\n";
while (<FH>) {
	chomp;
	next unless ($_ =~ m/^\d+,/);
	my ($num,$gen,$id,$source,$compname,$sid,$str) = split(/,/,$_,7);
	$str =~ s/\|/,/g;
	$sid = "" if ($sid eq "");
	my $t2 = parseTime($gen);
	my $descr = $source."/".$id." - ".$str;
	if (exists $ids{$source."/".$id}) {
		$descr = $ids{$source."/".$id}." ".$descr;
	}
	
	print $t2."|EVTX|".$compname."|".$sid."|".$descr."\n";
}
close(FH);

sub parseTime {
# 2011-08-26 07:58:46
	my $t = shift;
	my ($date,$time) = split(/\s/,$t,2);
	my($yr,$mon,$day) = split(/-/,$date,3);
	$mon =~ s/^0//;
	my($hr,$min,$sec) = split(/:/,$time,3);
	return timegm($sec,$min,$hr,$day,($mon - 1),$yr);
}

sub usage {
	print "To use this script, first run the following LogParser command:\n";
	print "\n";
	print "logparser -i:evt -o:csv \"Select RecordNumber,TimeGenerated,EventID,".
	      "SourceName,ComputerName,SID,Strings from <path\\*.evtx>\" > output\.txt\n";
	print "\n";
	print "Then add the events to the TLN events file by running:\n";
	print "\n";
	print "evtxparse output\.txt >> events\.txt\n";
	print "\n";
	print "copyright 2012 Quantum Analytics Research, LLC\n";
	print "Author: H. Carvey, keydet89\@yahoo\.com";
	print "\n";
	exit -1;
}

sub eventMap {
	my $file = shift;
	my %events;
	open(FH,"<",$file) || die "Could not open $file: $!\n";
	while(<FH>) {
		next if ($_ =~ m/^#/ || $_ =~ m/^\s+/);
		chomp;
		my ($id,$msg) = split(/:/,$_,2);
		$events{$id} = $msg;
	}
	close(FH);
	return %events;
}