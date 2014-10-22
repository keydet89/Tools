#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# Script to parse exported Facebook chat messages; export the 
# individual messages to text (.txt) files in a single directory;
# output is in csv format
#
# The following is the format of the artifacts, as extracted via 
# EnCase.  The format has been redacted, and fits all on one line
# (wrapped here for clarity):
# for (;;);{"t":"msg","c":"p_<num>","ms":[{"type":"msg","msg":{
# "text":"<msg>","time":<num_13>,"clientTime":<num_13>,
# "msgID":"<num>"},"from":<id>,"to":<id>,"from_name":"<name>",
# "to_name":"<name>","from_first_name":"<first_name>",
# "to_first_name":"<first_name>"}]}
#
# Ref: http://www.fbiic.gov/public/2011/jul/Facebook_Forensics-Finalized.pdf
#
# usage: fb.pl <dir> [> output.csv]
#
# copyright 2012 Quantum Analytics Research LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
use strict;
use JSON;

my $dir = shift;
die "Directory not found.\n" unless (-e $dir && -d $dir);
$dir .= "\\" unless ($dir =~ m/\\$/);
my @files;

opendir(DIR,$dir) || die "Can't open ".$dir.": $!\n";
@files = grep {/\.txt$/ && -f "$dir\\$_"}readdir(DIR);
closedir(DIR);

print "Message ID,From,FB ID,To,FB ID,Content,Date (UTC)\n";
foreach my $f (@files) {
	parseFile($dir.$f);
}

sub parseFile {
	my $file = shift;
	my $hash;

	open(FH,'<',$file) || die "Could not open ".$file.": $!\n";
	while(<FH>) {
		chomp;
		my $json = (split(/;/,$_))[3];
		$hash = decode_json($json);
	}
	close(FH);

	foreach my $i (@{$$hash{'ms'}}) {
# This line strips commas out of messages, so that everything
# comes out neater in the final csv		
		my $content = $i->{'msg'}->{'text'};
		$content =~ s/,//g;
		
		print $i->{'msg'}->{'msgID'}.",".$i->{'from_name'}.",".$i->{'from'}.",".$i->{'to_name'}.",".$i->{'to'}.
		      ",".$i->{'msg'}->{'text'}.",".gmtime(int($i->{'msg'}->{'time'}/1000))." Z\n";

#		print "Message #: ".$i->{'msg'}->{'msgID'}."\n";
#		print "\n";
#		print "From     : ".$i->{'from_name'}."\n";
#		print "FB ID    : ".$i->{'from'}."\n";
#		print "\n";
#		print "To       : ".$i->{'to_name'}."\n";
#		print "FB ID    : ".$i->{'to'}."\n";
#		print "\n";
#		print "Content  : ".$i->{'msg'}->{'text'}."\n";
#		print "\n";
#		print "Date     : ".gmtime(int($i->{'msg'}->{'time'}/1000))."\n";
	}
}
