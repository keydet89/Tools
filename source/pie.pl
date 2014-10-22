#! c:\perl\bin\perl.exe
#------------------------------------------------------------
# pie.pl - stripped-down version of parseie.pl, used to parse
#  headers of index.dat file and provide an overview of what's 
#  available.
#
# By default, the IE index.dat file is created for all user accounts.
# However, it is not populated unless the WinInet API is used for 
# off-system comms.  Running this script will parse the headers of the
# index.dat file (if found) and give stats that would give you info 
# on which file(s) to target.  For example, finding a "Default User" or
# "LocalService" account with a populated index.dat file might indicate
# malware using the WinInet API, running with System-level privileges.
#
# History
#  20130305 - 'created'; the script has been in-process for some time,
#             but was really finalized on this date.
#
# References 
#   http://www.forensicswiki.org/wiki/Internet_Explorer_History_File_Format
#   http://www.mcafee.com/us/resources/white-papers/foundstone/wp-pasco.pdf
#
# copyright 2013 QAR, LLC
# Author: H. Carvey, keydet89@yahoo.com
#------------------------------------------------------------
use strict;

my $VERSION = 20130305;

my $file = shift || die "You must enter a file name\.\n";
my $data;

open(FH,"<",$file) || die "Could not open $file: $!\n";
binmode(FH);

seek(FH,0,0);
read(FH,$data,72);

my %hdr = parseHeader($data);
die "Not a valid header\.\n" if ($hdr{valid} == 0);

print  "File size              : ".$hdr{size}."\n";
printf "Hash Table Offset      : 0x%x\n",$hdr{hash_ofs};
print  "Number of blocks       : ".$hdr{num_blocks}."\n";
print  "Number of alloc. blocks: ".$hdr{num_alloc_blocks}."\n";
print  "\n";

# Get the cache directory table, in a Perl hash
seek(FH,72,0);
read(FH,$data,4);
my $num = unpack("V",$data);
seek(FH,72,0);
read(FH,$data, ($num * 12) + 4);
my %tab = parseDirTable($data);

foreach (0..(scalar(keys %tab) - 1)) {
	print "Dir: ".$tab{$_}{name}."  Files: ".$tab{$_}{pages}."\n";
}

close(FH);

#-----------------------------------------------------------
# parseHeader()
# 
#-----------------------------------------------------------
sub parseHeader {
	my $data = shift;
	my %hdr = ();
	
	$hdr{sig} = substr($data,0,28);
	if ($hdr{sig} =~ m/^Client UrlCache MMF/) {
		$hdr{valid} = 1;
	}
	else {
		$hdr{valid} = 0;
	}
	
	$hdr{size} = unpack("V",substr($data,28,4));
	$hdr{hash_ofs} = unpack("V",substr($data,32,4));
	$hdr{num_blocks} = unpack("V",substr($data,36,4));
	$hdr{num_alloc_blocks} = unpack("V",substr($data,40,4));
	$hdr{non_rel_cache} = unpack("V",substr($data,64,4));
	
	return %hdr;
}

#-----------------------------------------------------------
# parseDirTable()
# 
#-----------------------------------------------------------
sub parseDirTable {
	my $data = shift;
	my %table = ();
	my $num = unpack("V",substr($data,0,4));
	
	foreach my $n (0..($num - 1)) {
		my $entry = substr($data,4 + (12 * $n),12);
    $table{$n}{name} = substr($entry,4,8);
    $table{$n}{pages} = unpack("V",substr($entry,0,4));
	}
	return %table;
}
