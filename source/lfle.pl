#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# lfle.pl - script to parse EVT records from unstructured data; can be
#           used to parse unallocated space, pagefile, memory, as well as
#           EVT files reported as "corrupt".
#
# Logic:
#  - Look for "LfLe" 'magic number' on a 4-byte border
#  - Get the preceding 4 bytes, as the size of the record
#    - skip if size >= 2048, or if size == 0x30|0x28
#    - if first and last 4 bytes of the record are the same, assume
#      a 'valid' record and parse
#
# Output to STDOUT in 5-field TLN format (pipe delimited)
#
# copyright 2014 QAR, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
use strict;

my $file = shift;
die "You must enter a filename\.\n" if ($file eq "");
die $file." not found\.\n" unless (-e $file);

my $size = (stat($file))[7];
my $data;
my $ofs;

my %types = (0x0001 => "Error",
             	0x0010 => "Failure",
             	0x0008 => "Success",
             	0x0004 => "Info",
             	0x0002 => "Warn");

open(FH,"<",$file) || die "Could not open $file: $!\n";
binmode(FH);
while ($ofs < $size) {
	seek(FH,$ofs,0);
	read(FH,$data,4);
	if (unpack("V",$data) == 0x654c664c) {
#	printf "Magic number located at offset 0x%x\n",$ofs;
		seek(FH,$ofs - 4,0);
		read(FH,$data,4);
		my $l = unpack("V",$data);
		if ($l < 0x800) {
# If the record size is larger than 2K, we're going to skip it. Most records
# aren't this big, and this will help keep us from reading off the end of the
# file when the value read as the record size is too large	
			seek(FH,$ofs - 4,0);
			read(FH,$data,$l);
			my $f = unpack("V",substr($data,$l - 4,4));
#			printf "Possible record located at offset 0x%08x; Length = 0x%x, Final Length = 0x%x\n",$ofs - 4,$l,$f;
			if ($l == $f) {
				if ($l == 0x30) {
# skip over header records					
#				print "\t**HDR Record\n";
					$ofs += 0x30;
				}
				elsif ($l == 0x28) {
# also skip EOF records					
#				print "\t**EOF Record\n";	
					$ofs += 0x28;
				}
				else {
					my %r = parseRec($data);
					my $desc = $r{source}."/".$r{evt_id}.";".$types{$r{evt_type}}.";".$r{strings};
					print $r{time_gen}."|EVT|".$r{computername}."|".$r{sid}."|".$desc."\n";
					$ofs += $l;
				}
			}
		}	
		else {
			$ofs += 4;
		}
	}
	else {
		$ofs += 4;
	}
}
close(FH);

#---------------------------------------------------------------------
# parseRec()
# Parse the binary Event Record
# References:
#   http://msdn.microsoft.com/en-us/library/aa363646(VS.85).aspx  
#---------------------------------------------------------------------
sub parseRec {
	my $data = shift;
	my %rec;
	my $hdr = substr($data,0,56);
	($rec{length},$rec{magic},$rec{rec_num},$rec{time_gen},$rec{time_wrt},
	$rec{evt_id},$rec{evt_id2},$rec{evt_type},$rec{num_str},$rec{category},
	$rec{c_rec},$rec{str_ofs},$rec{sid_len},$rec{sid_ofs},$rec{data_len},
	$rec{data_ofs}) = unpack("V5v5x2V6",$hdr); 
	
# Get the end of the Source/Computername field
	my $src_end;
	($rec{sid_len} == 0) ? ($src_end = $rec{str_ofs}) : ($src_end = $rec{sid_ofs});
	my $s = substr($data,0x38,$src_end);
	($rec{source},$rec{computername}) = (split(/\x00\x00/,$s))[0,1];
	$rec{source} =~ s/\x00//g;
	$rec{computername} =~ s/\x00//g;
	
# Get SID
	if ($rec{sid_len} > 0) {
		my $sid = substr($data,$rec{sid_ofs},$rec{sid_len});
		$rec{sid} = translateSID($sid);
	}
	else {
		$rec{sid} = "N/A";
	}
	
# Get strings from event record
	my $strs = substr($data,$rec{str_ofs},$rec{data_ofs} - $rec{str_ofs});
	my @str = split(/\x00\x00/,$strs, $rec{num_str});
	$rec{strings} = join(',',@str);
	$rec{strings} =~ s/\x00//g;
	$rec{strings} =~ s/\x09//g;
	$rec{strings} =~ s/\n/ /g;
	$rec{strings} =~ s/\x0D//g;

	return %rec;
}

#---------------------------------------------------------------------
# translateSID()
# Translate binary data into a SID
# References:
#   http://blogs.msdn.com/oldnewthing/archive/2004/03/15/89753.aspx  
#   http://support.microsoft.com/kb/286182/
#   http://support.microsoft.com/kb/243330
#---------------------------------------------------------------------
sub translateSID {
	my $sid = $_[0];
	my $len = length($sid);
	my $revision;
	my $dashes;
	my $idauth;
	if ($len < 12) {
# Is a SID ever less than 12 bytes?		
		return "SID less than 12 bytes";
	}
	elsif ($len == 12) {
		$revision = unpack("C",substr($sid,0,1));
		$dashes   = unpack("C",substr($sid,1,1));
		$idauth   = unpack("H*",substr($sid,2,6));
		$idauth   =~ s/^0+//g;
		my $sub   = unpack("V",substr($sid,8,4));
		return "S-".$revision."-".$idauth."-".$sub;
	}
	elsif ($len > 12) {
		$revision = unpack("C",substr($sid,0,1));
		$dashes   = unpack("C",substr($sid,1,1));
		$idauth   = unpack("H*",substr($sid,2,6));
		$idauth   =~ s/^0+//g;
		my @sub   = unpack("V*",substr($sid,8,($len-2)));
		my $rid   = unpack("v",substr($sid,24,2));
		my $s = join('-',@sub);
		return "S-".$revision."-".$idauth."-".$s;
#		return "S-".$revision."-".$idauth."-".$s."-".$rid;
	}
	else {
# Nothing to do		
	}
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
#
# Usage: see probe()
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