package JumpList;
#---------------------------------------------------------------------
# JumpList - module to parse Windows 7 Jump Lists, on a binary level
#
# Windows 7 Jump Lists (*.automaticDestinations-ms) are based on the
# OLE/Compound document format, and the individual numbered streams are
# based the Shortcut/LNK file format.  There is no public documentation 
# for the format of the DestList stream (which appears to be used as 
# an MRU/MFU listing).
# 
# The purpose of this module is to parse Jump Lists on a binary level
# without using any proprietary modules (as of Perl 5.12, the OLE::Storage
# module appears to be deprecated, or at least contains deprecated code).
# This module will allow the programmer to parse a single 
# *.automaticDestinations-ms Jump List file, and return both the DestList
# and the numbered streams in Perl hashes.  This is intended to allow the 
# programmer to add a GUI, or create specialized output formats (TLN, XML)
# as needed.
# 
# Change History:
#   20111229 - updated get_stream() to take a stream name instead of a 
#              size and start sector; that lookup is now handled internally
#   20110815 - updated
#   20110812 - created
#
# Reference:
#   http://msdn.microsoft.com/en-us/library/dd942138(v=prot.13).aspx
#
# copyright 2011-2012 Quantum Research Analytics, LLC
#
# This code is provided under GPLv3, http://www.gnu.org/copyleft/gpl.html
#---------------------------------------------------------------------
use strict;
use Carp;
use Exporter;

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

$VERSION     = 20111230;
@ISA         = qw(Exporter);
@EXPORT      = ();
@EXPORT_OK   = qw(new getDirectoryTable getStream getDestList);

# Global variables
my $file;
my @fat_sectors = ();
my @sat;
my @ssat;
my @dir_sectors;
my %directory_table;
my @root_entry_list;
my @root_lookup_table;
my @ssat_sectors;
my %destlist;


END {
	undef $file;
	undef @fat_sectors;
	undef @sat;
	undef @ssat;
	undef @dir_sectors;
	undef %directory_table;
	undef @root_entry_list;
	undef @root_lookup_table;
	undef @ssat_sectors;
	undef %destlist;
}

# self reference
my $self = {};			

#---------------------------------------------------------------------
# new()
# 
#---------------------------------------------------------------------      	    
sub new {
	my $class = shift;
	$file = shift;
	
  @fat_sectors        = ();
	@sat                = ();
	@ssat               = ();
	@dir_sectors        = ();
	%directory_table    = {};
	@root_entry_list    = ();
	@root_lookup_table  = ();
	@ssat_sectors       = ();
	%destlist           = {};
	
	if (-e $file && -f $file) {
		my @v = get_headers($file);
		if ($v[0] == 0xe011cfd0 && $v[1] == 0xe11ab1a1) {
			_init();
			return bless($self, $class);
		}
		else {
			warn("Incorrect file signature.");
			return;
		}
	}
	else {
		warn("File not found.");
		return;
	}
}

#---------------------------------------------------------------------
# get_headers()
# 
# called by new()
#---------------------------------------------------------------------  
sub get_headers {
	my $file = shift;
	my $data;
	open(FH,"<",$file) || warn "Could not open file: $!\n";
	binmode(FH);

	seek(FH,0,0);
	read(FH,$data,512);
	close(FH);
	my $d = substr($data,0,80);
	my @vals = unpack("VVx16v5x6V10",$d);

#	printf "Header Signature: 0x%08x 0x%08x\n",$vals[0],$vals[1];
#	printf "Minor Version   : 0x%08x\n",$vals[2];
#	printf "Major Version   : 0x%08x\n",$vals[3];
#	printf "Byte Order      : 0x%08x\n",$vals[4];
#	printf "Sector Shift    : 0x%08x\n",$vals[5];
#	printf "Mini Sec Shift  : 0x%08x\n",$vals[6];
#	print  "Num Dir Sectors : $vals[7]\n";
#	print  "Num FAT Sectors : $vals[8]\n";
#	printf "1st Dir Loc     : 0x%08x\n",$vals[9];
#	print  "Tx Sig Number   : $vals[10]\n";
#	printf "Mini FAT Start  : 0x%08x\n",$vals[12];
#	print  "# Mini FAT Sect : $vals[13]\n";
#	printf "First DIFAT Sect: 0x%08x\n",$vals[14];
#	print  "# DIFAT Sect    : $vals[15]\n";
#	print "\n";

# @fat_sectors is actually the Master Sector Allocation Table	
	push(@fat_sectors,0x00);
 	
# if the number of FAT sectors is > 1, we need to populate the list
# of sectors used	
	if ($vals[8] > 1) {
		my @f = unpack("V*",substr($data,0x50,4 * ($vals[8] - 1)));
		push(@fat_sectors,@f);
	}
	
	return ($vals[0],$vals[1]);
}

#---------------------------------------------------------------------
# _init()
# 
# called by new()
#--------------------------------------------------------------------- 
sub _init {
#	my $class = shift;
	get_sat();
	
	@dir_sectors = get_lookup_array(1);
	
	parse_directory_table();
	
	@root_entry_list = get_lookup_array($directory_table{"Root Entry"}{start_sector});
	
	get_root_lookup_table();
	delete $directory_table{"Root Entry"};
	
	@ssat_sectors = get_lookup_array(2);
	
	get_ssat_array();
}

#---------------------------------------------------------------------
# getDirectoryTable()
# 
# Returns %directory_table
#---------------------------------------------------------------------  
sub getDirectoryTable {
	my $class = shift;
	return %directory_table;
}

#---------------------------------------------------------------------
# getDestList()
# 
# Input: Nothing required (values pulled from %directory_table)
# Returns hash of hashes containing DestList stream contents
#---------------------------------------------------------------------
sub getDestList {
	my $class = shift;
	my $stream = get_stream("DestList");
	return parse_destlist_stream($stream);
}	

#---------------------------------------------------------------------
# getStream()
# 
# calls internal get_stream() function; 
# Input: Name of stream (from directory table); not for use with the
#        DestList stream; that's handled separately
# Output: binary stream 
#---------------------------------------------------------------------
sub getStream {
	my $class = shift;
	return get_stream(shift);
}
#---------------------------------------------------------------------
# getSAT()
# 
#---------------------------------------------------------------------  
sub get_sat {
	my $buffer;
	my $data;
	
	open(FH,"<",$file);
	binmode(FH);
	foreach (0..(scalar(@fat_sectors) - 1)) {
		seek(FH,($fat_sectors[$_] + 1) * 512,0);
		read(FH,$data,512);
		$buffer .= $data;
	}
	close(FH);
	undef @fat_sectors;
	@sat = read_sat($buffer);
}

#---------------------------------------------------------------------
# get_lookup_array()
#  - uses @sat
#---------------------------------------------------------------------  
sub get_lookup_array {
	my $indx = shift;
	my @list = ();
	my $tag = 1;
	
	while($tag) {
		if ($sat[$indx] == -2) {
			push(@list,$indx);
			$tag = 0;
		}
		else {
			push(@list,$indx);
			$indx = $sat[$indx];
		}
	}
	return @list;
}

#---------------------------------------------------------------------
# parse_directory_table()
# 
#--------------------------------------------------------------------- 
sub parse_directory_table {
	my $stream;
	my $buffer;
	open(FH,"<",$file);
	binmode(FH);
	foreach (@dir_sectors) {
		seek(FH,($_ + 1) * 512,0);
		read(FH,$buffer,512);
		$stream .= $buffer;
	}
	
	my $size = 128;
	my $num = ((length($stream))/$size) - 1;
	
	my %entry;
	foreach my $i (0..$num) {
		my $data = substr($stream,$i * $size,$size);
		my $name = substr($data,0,64);
		$name =~ s/\00//g;
		next if ($name eq "");
		$entry{$name}{type} = unpack("c",substr($data,66,1));
		$entry{$name}{color} = unpack("c",substr($data,67,1));
		$entry{$name}{leftsibling} = unpack("V",substr($data,68,4));
#		printf "  Left Sibling : 0x%x\n",$entry{leftsibling};
		$entry{$name}{rightsibling} = unpack("V",substr($data,72,4));
#		printf "  Right Sibling: 0x%x\n",$entry{leftsibling};
		$entry{$name}{childid} = unpack("V",substr($data,76,4));
#		printf "  Child ID     : 0x%x\n",$entry{childid};
		$entry{$name}{state}   = unpack("V",substr($data,96,4));
		
		my ($c1,$c2) = unpack("VV",substr($data,100,8));
		$entry{$name}{creation} = getTime($c1,$c2) if ($c1 != 0 && $c2 != 0);
		my ($m1,$m2) = unpack("VV",substr($data,108,8));
		$entry{$name}{modification} = getTime($m1,$m2) if ($m1 != 0 && $m2 != 0);
		
		$entry{$name}{start_sector} = unpack("V",substr($data,116,4));
		
		my ($s1,$s2)  = unpack("VV",substr($data,120,8));
		$entry{$name}{size} = $s1 if ($s2 == 0);
	}
	%directory_table = %entry;
}

#---------------------------------------------------------------------
# read_sat()
# return a sector address table; used by get_sat()
#--------------------------------------------------------------------- 
sub read_sat {
	my $data = shift;
	
	my @list = ();
	my $tag = 1;
	my $count = 0;

	my @t = unpack("l*",$data);
	while ($tag) {
		$list[$count] = $t[$count];
		$tag = 0 if ($t[$count] == -1);
# The following line is kind of a hack; sometimes, the SAT doesn't end
# with a "-1" entry, but it's the last one listed in the final SAT sector.
# This may happen if the application has a file open, or the system is 
# acquired live.  In short, once you've gone through the entire SAT, if
# you haven't reached a -1/0xffffffff, stop.		
		$tag = 0 if ($count == (length($data)/4));
		$count++;
	}
	return @list;
}

#---------------------------------------------------------------------
# get_root_lookup_table()
#
# This is probably some of the THE most important code in the module;
# this code allows the streams to be reassembled from the SSAT (streams
# smaller than 4096 bytes).
#---------------------------------------------------------------------
sub get_root_lookup_table {
	my $i = 0;
	foreach my $r (0..(scalar(@root_entry_list) - 1)) {
		foreach my $t (0..7) {
			$root_lookup_table[$i] = (($root_entry_list[$r] + 1) * 512) + ($t * 64);
			$i++;
		}
	}	
}

#---------------------------------------------------------------------
# get_ssat_array()
# 
#---------------------------------------------------------------------
sub get_ssat_array {
	my $stream;
	my $data;
	open(FH,"<",$file);
	binmode(FH);
	foreach (@ssat_sectors) {
		seek(FH,($_ + 1) *512,0);
		read(FH,$data,512);
		$stream .= $data;
	}
	close(FH);
# Now to populate the @ssat list
	my $tag = 1;
	my $count = 0;
	my @t = unpack("l*",$stream);
	while($tag) {
		$ssat[$count] = $t[$count];
		$tag = 0 if ($t[$count] == -1);
		$count++;
	}
# At this point, the @ssat list should be populated
}

#---------------------------------------------------------------------
# get_stream()
# 
# Internal function; given a stream name (all stream names within a
# Jump List file appear to be unique), it looks up the stream start_sector
# and size in the directory table, and returns the binary stream
#---------------------------------------------------------------------
sub get_stream {
	my $name = shift;
	my $indx = $directory_table{$name}{start_sector};
	my $size = $directory_table{$name}{size};
	my $str;
	my $data;
	
# Where you go to assemble the stream depends on the size;
# 4096 bytes or more, and the stream is found in the SAT,
# otherwise it's in the SSAT (sectors = 64 bytes)
	if ($size >= 4096) {
		my @list = get_lookup_array($indx);
		open(FH,"<",$file);
		binmode(FH);
		foreach my $i (0..(scalar(@list) - 1)) {
			seek(FH,($list[$i] + 1) * 512,0);
			read(FH,$data,512);
			$str .= $data;
		}
		close(FH);
	}
	else {
		my @list = get_stream_sector_array($indx);
		open(FH,"<",$file);
		binmode(FH);
		foreach my $i (0..(scalar(@list) - 1)) {
			seek(FH,$root_lookup_table[$list[$i]],0);
			read(FH,$data,64);
			$str .= $data;
		}
		close(FH);
	}
	
	return substr($str,0,$size);
}

#---------------------------------------------------------------------
# get_stream_sector_array()
# 
#---------------------------------------------------------------------
sub get_stream_sector_array {
	my $indx = shift;
	my @list = ();
	my $tag = 1;
	while($tag) {
		push(@list,$indx);
		($ssat[$indx] == -2)?($tag = 0):($indx = $ssat[$indx]);
	}
	return @list;
}

#---------------------------------------------------------------------
# parse_destlist_stream()
# 
# Parses the DestList stream; populates the %destlist hash-of-hashes
# Key: position
#         mrutime - FILETIME
#         str     - string
#         uname   - system name
#---------------------------------------------------------------------
sub parse_destlist_stream {
	my $stream = shift;
	my %destlist;
	my @num = unpack("VV",substr($stream,4,8));
	my @num2 = unpack("VV",substr($stream,24,8));
#if ($num[1] == 0) {
#	print "Number of entries = ".$num[0]."\n";
#}
#print "Valid header.\n" if ($num2[0] == $num[0] && $num2[1] == $num[1]);

# Start reading the first "object" or structure
	my $offset = 0x20;
	foreach (1..$num[0]) {
		my $str_sz = unpack("v",substr($stream,$offset + 112,2));

# Total structure size = 112 + 2 + ($str_sz * 2) bytes
		my $sz = 112 + 2 + ($str_sz * 2);
		my $data = substr($stream, $offset, $sz);
		my %st = parse_destlist_struct($data);
		
		$destlist{$st{position}}{mrutime} = $st{mrutime};
		$destlist{$st{position}}{str}     = $st{str};
		$destlist{$st{position}}{uname}   = $st{uname};
		$offset += $sz;
	}
	return %destlist;
}

#---------------------------------------------------------------------
# parse_destlist_struct()
# 
# Parses individual DestList stream structures
#---------------------------------------------------------------------
sub parse_destlist_struct {
	my $data = shift;
	my %struct;
	
#	$struct{t1} = getTime(unpack("VV",substr($data,24,8))); 
#	$struct{t2} = getTime(unpack("VV",substr($data,56,8)));
	my @t = unpack("VV",substr($data,100,8));
	$struct{mrutime} = getTime($t[0],$t[1]);
	$struct{uname} = substr($data,72,16);
	$struct{uname} =~ s/\00//g;
	
	my @mark = unpack("VV",substr($data,88,8));
	if ($mark[1] == 0) {
		$struct{position} = sprintf "%x",$mark[0];
	}
	
	my $sz = unpack("v",substr($data,112,2));
	$struct{str} = substr($data,114,($sz * 2));
	$struct{str} =~ s/\00//g;
	return %struct;
}

#-------------------------------------------------------------
# getTime()
# Translate FILETIME object (2 DWORDS) to Unix time, to be passed
# to gmtime() or localtime()
#
# The code was borrowed from Andreas Schuster's excellent work
#-------------------------------------------------------------
sub getTime($$) {
	my $lo = shift;
	my $hi = shift;
	my $t;

	if ($lo == 0 && $hi == 0) {
		$t = 0;
	} else {
		$lo -= 0xd53e8000;
		$hi -= 0x019db1de;
		$t = int($hi*429.4967296 + $lo/1e7);
	};
	$t = 0 if ($t < 0);
	return $t;
}
1;