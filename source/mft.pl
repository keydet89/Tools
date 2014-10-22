#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# Simple $MFT parser 
#   - detects ADSs (prints hex dump if they're resident), and
#     Extended Attributes (may indicate ZeroAccess - 
#     http://journeyintoir.blogspot.com/2012/12/extracting-zeroaccess-from-ntfs.html)
#
#
# To-Do:
#   - Update lookup table creation to account for sequence numbers
#     and identify orphaned files
#
#
# http://msdn.microsoft.com/en-us/library/bb470206%28VS.85%29.aspx
#
# copyright 2014 QAR, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
use strict;

my $file = shift || die "You must enter a filename.\n";
die "Could not find $file\n" unless (-e $file);

my $record_sz = getRecordSize($file);
my %tab = buildLookupTable($file,$record_sz);

my %lookup;
foreach my $c (sort {$a <=> $b} keys %tab) {
	$lookup{$c} = getPath($c);
}
undef %tab;

#print "Lookup table built\.\n";
#foreach (sort {$a <=> $b} keys %lookup) {
#	print $_."  ".$lookup{$_}."\n";
#}

# Now that we have a table of paths, we need to run through the MFT
# again, and parse out all of the information; we can replace the 
# record number with the value from the lookup table (ie, %ftable)

parseMFT($file,$record_sz);

#-------------------------------------------------------------
# getRecordSize() - record size is included in the record 
#   header, as a DWORD at offset 0x1c
#  
#-------------------------------------------------------------
sub getRecordSize {
	my $file = shift;
	my $sig;
	my $ofs = 0;
	my $data;
	my $sz = 1024;
	
	open(FH,"<",$file);
	binmode(FH);
	seek(FH,$ofs,0);
	read(FH,$data,4);
	
	if ($data eq "FILE") {
		seek(FH,0x1c,0);
		read(FH,$data,4);
		$sz = unpack("V",$data);
	}
	close(FH);
	return $sz;
}

#-------------------------------------------------------------
# getPath()
# 
#-------------------------------------------------------------
sub getPath {
	my $rec = shift;
	next if ($rec > 11 && $rec < 16);
	my @path;
#	print "  Checking record ".$rec."...\n";
	my $root;
	while ($root ne "\." && $root ne "[Orphan]") {
		if (exists $tab{$tab{$rec}{parent_ref}} && ($tab{$tab{$rec}{parent_ref}}{seq} == $tab{$rec}{parent_seq})) {	
			$root = $tab{$rec}{name};
#			print "    Root: ".$root."\n";
			push(@path,$root);
			$rec = $tab{$rec}{parent_ref};
		}
		else {
			$root = "[Orphan]";
#			print "    Root: ".$root."\n";
			push(@path,$root);
		}
	}
#	print "  Path: ".join('\\',reverse @path)."\n";
	return join('\\',reverse @path);
}

#-------------------------------------------------------------
# buildLookupTable()
# 
#-------------------------------------------------------------
sub buildLookupTable {
	my $file = shift;
	my $sz = shift || 1024;
	my $count = 0;
	my $size = (stat($file))[7];
	my $data;
	my %mft;
	my %lookup;
	
	open(MFT,"<",$file) || die "Could not open $file to read: $!\n";
	binmode(MFT);
	while(($count * $sz) < $size) {
		seek(MFT,$count * $sz,0);
		read(MFT,$data,$sz);
		my %names;
		my $record;
		my $hdr = substr($data,0,0x30);
		%mft = parseRecordHeader($hdr);
		
		$record = $count;
		$count++;
# record must be good, not "BAAD"		
# if the record is not a base record, skip it	
# record must be a directory or file, in use	
#		if (($mft{sig} eq "FILE") && ($mft{base_rec} == 0) && ($mft{flags} == 0x03)) {
		if (($mft{sig} eq "FILE") && ($mft{base_rec} == 0) && ($mft{flags} & 0x01)) {
			my $ofs = $mft{attr_ofs};
			my $next = 1;
			while ($next == 1) {
				my $attr = substr($data,$ofs,16);
				my ($type,$len,$res,$name_len,$name_ofs,$flags,$id) = unpack("VVCCvvv",$attr);
				$next = 0 if ($type == 0xffffffff || $type == 0x0000);
# $SIA is always resident, so the extra check doesn't matter
				if ($type == 0x10 && $res == 0) {
# Since we're building a lookup table using record numbers and names, 
# we don't need anything from the $STANDARD_INFORMATION attribute (not at 
# the moment)			
				}
# $FNA is always resident, so the extra check doesn't matter
				elsif ($type == 0x30 && $res == 0) {
					my %fn = parseFNAttr(substr($data,$ofs,$len));
					$names{$fn{name_len}}{name} = $fn{name};
					$names{$fn{name_len}}{parent_ref} = $fn{parent_ref};		
					$names{$fn{name_len}}{parent_seq} = $fn{parent_seq};
				}
# This is where other attributes would get handled, but we're not
# interested in other attributes
				else{}		
				$ofs += $len;
			}
# Get the longest name of all $FILE_NAME attr in the record	
			my $n = (reverse sort {$a <=> $b} keys %names)[0];
			$lookup{$mft{rec_num}}{name} = $names{$n}{name} if ($names{$n}{name} ne "");
			$lookup{$mft{rec_num}}{parent_ref} = $names{$n}{parent_ref};
			$lookup{$mft{rec_num}}{parent_seq} = $names{$n}{parent_seq};
			$lookup{$mft{rec_num}}{seq} = $mft{seq};
		}
	}
	close(MFT);
	return %lookup;
}

#-------------------------------------------------------------
# parseRecordHeader() - takes 48 bytes, returns %mft hash with
#   most of the values populated (not all are needed)
#-------------------------------------------------------------
sub parseRecordHeader {
	my $hdr = shift;
	my %mft;
# length($data) should be 48 bytes
	$mft{sig} = substr($hdr,0,4);
	$mft{seq} = unpack("v",substr($hdr,0x10,2));
	$mft{linkcount} = unpack("v",substr($hdr,0x12,2));
	$mft{attr_ofs} = unpack("v",substr($hdr,0x14,2));
	$mft{flags} = unpack("v",substr($hdr,0x16,2));
	$mft{used_sz} = unpack("V",substr($hdr,0x18,4));
	$mft{alloc_sz} = unpack("V",substr($hdr,0x1c,4));
	
#	This is a hack for 32-bit Perl; the MFT record number is maintained in the 
# header in 4 bytes, but a reference number includes the use of 6 bytes for 
# the record number.	In this case, if the first 4 bytes of the base record
# file ref # are 0, we're assuming that the record itself is a base record
# pg 284, "File System Forensic Analysis"
	$mft{base_rec} = unpack("V",substr($hdr,0x20,4));
	$mft{next_attr_id} = unpack("v",substr($hdr,0x28,2));
	$mft{rec_num} = unpack("V",substr($hdr,0x2c,4));
	return %mft;
}

#-------------------------------------------------------------
# parseSIAttr()
# 
#-------------------------------------------------------------
sub parseSIAttr {
	my $si = shift;
	my %si;
	my ($type,$len,$res,$name_len,$name_ofs,$flags,$id,$sz_content,$ofs_content) 
		= unpack("VVCCvvvVv",substr($si,0,22));
		
	my $content = substr($si,$ofs_content,$sz_content);
	my ($t0,$t1) = unpack("VV",substr($content,0,8));
	$si{c_time} = getTime($t0,$t1);
	my ($t0,$t1) = unpack("VV",substr($content,8,8));
	$si{m_time} = getTime($t0,$t1);
	my ($t0,$t1) = unpack("VV",substr($content,16,8));
	$si{mft_m_time} = getTime($t0,$t1);
	my ($t0,$t1) = unpack("VV",substr($content,24,8));
	$si{a_time} = getTime($t0,$t1);
	$si{flags} = unpack("V",substr($content,32,4));	
		
	return %si;	
}

#-------------------------------------------------------------
# parseFNAttr()
# 
#-------------------------------------------------------------
sub parseFNAttr {
	my $fn = shift;
	my %fn;
	my ($type,$len,$res,$name_len,$name_ofs,$flags,$id,$sz_content,$ofs_content) 
		= unpack("VVCCvvvVv",substr($fn,0,22));
	my $content = substr($fn,$ofs_content,$sz_content);
	
#	This is a hack for 32-bit Perl; the MFT record number is maintained in the 
# header in 4 bytes, but a reference number includes the use of 6 bytes for 
# the record number.  
	$fn{parent_ref} = unpack("V",substr($content,0,4));
	$fn{parent_seq} = unpack("v",substr($content,6,2));
	my ($t0,$t1) = unpack("VV",substr($content,8,8));
	$fn{c_time} = getTime($t0,$t1);
	my ($t0,$t1) = unpack("VV",substr($content,16,8));
	$fn{m_time} = getTime($t0,$t1);
	my ($t0,$t1) = unpack("VV",substr($content,24,8));
	$fn{mft_m_time} = getTime($t0,$t1);
	my ($t0,$t1) = unpack("VV",substr($content,32,8));
	$fn{a_time} = getTime($t0,$t1);
	
	$fn{flags} = unpack("V",substr($content,56,4));
	$fn{len_name} = unpack("C",substr($content,64,1));
	$fn{namespace} = unpack("C",substr($content,65,1));

	$fn{len_name} = $fn{len_name} * 2;
#	$fn{len_name} = $fn{len_name} * 2 if ($fn{namespace} > 0);
	$fn{name} = substr($content,66,$fn{len_name});
	$fn{name} = cleanStr($fn{name});
#	$fn{name} = cleanStr($fn{name}) if ($fn{namespace} > 0);
#	$fn{name} =~ s/\00//g;
	$fn{name} =~ s/\x0c/\x2e/g;
	$fn{name} =~ s/[\x01-\x0f]//g;
	return %fn;
}

#-------------------------------------------------------------
# parseMFT() - does most of the work
# 
#-------------------------------------------------------------
sub parseMFT {
	my $file = shift;
	my $sz = shift || 1024;
	my %attr_types = (16 => "Standard Information",
                  48 => "File name",
                  64 => "Object ID",
                  128 => "Data",
                  144 => "Index Root",
                  160 => "Index Allocation",
                  176 => "Bitmap");

#-----------------------------------------------------------
# Flags from MFT entry header (use an AND/& operation)
#    00 00 deleted file
#    01 00 allocated file
#    02 00 deleted directory
#    03 00 allocated directory
#-----------------------------------------------------------

	my $count = 0;
	my $size = (stat($file))[7];
	my $data;
	my %mft;

	open(MFT,"<",$file) || die "Could not open $file to read: $!\n";
	binmode(MFT);
	my $t = 1;
	while(($count * $sz) < $size) {
		seek(MFT,$count * $sz,0);
		read(MFT,$data,$sz);
		
		my %mft = parseRecordHeader(substr($data,0,48));
		
#		my $test = unpack("V",substr($data,$mft{attr_ofs},4));
#		$t = 0 if ($test == 0xffffffff);
# using flags, perform an AND operation (ie, &) with flags
#  if ($mft{flags} & 0x0001) - allocated; else unallocated/deleted
#	 if ($mft{flags} & 0x0002) - folder/dir; else file	           
		printf "%-10d %-4s Seq: %-4d Links: %-4d\n",
		      $mft{rec_num},$mft{sig},$mft{seq},$mft{linkcount};
	  
	 	my @str;
	  if ($mft{flags} & 0x02) {
	  	push(@str, "[FOLDER]");
	  }
	  else {
	  	push(@str, "[FILE]");
	  }
	  push(@str, "[DELETED]") unless ($mft{flags} & 0x01);
	  push(@str,"[BASE RECORD]") if ($mft{base_rec} == 0);
	  print join(',',@str)."\n";
	  
	  if (%lookup) {
	  	if (exists $lookup{$mft{rec_num}}) {
	  		print $lookup{$mft{rec_num}}."\n";
	  	}
	  }
	  
		$count++;
		next unless ($mft{sig} eq "FILE");
	
		my $ofs = $mft{attr_ofs};
		my $next = 1;
		while ($next == 1) {
			my $attr = substr($data,$ofs,16);
			my ($type,$len,$res,$name_len,$name_ofs,$flags,$id) = unpack("VVCCvvv",$attr);
			$next = 0 if ($type == 0xffffffff || $type == 0x0000);
#			printf "  0x%04x %-4d %-2d  0x%04x 	0x%04x\n",$type,$len,$res,$name_len,$name_ofs unless ($type == 0xffffffff);
# $res == 0 -> data is resident
# $SIA is always resident, so the extra check doesn't matter
			if ($type == 0x10 && $res == 0) {
				my %si = parseSIAttr(substr($data,$ofs,$len));			
				print "    M: ".gmtime($si{m_time})." Z\n";
				print "    A: ".gmtime($si{a_time})." Z\n";
				print "    C: ".gmtime($si{mft_m_time})." Z\n";
				print "    B: ".gmtime($si{c_time})." Z\n";
			}
# $FNA is always resident, so the extra check doesn't matter
			elsif ($type == 0x30 && $res == 0) {
				my %fn = parseFNAttr(substr($data,$ofs,$len));
				print "  FN: ".$fn{name}."  Parent Ref: ".$fn{parent_ref}."/".$fn{parent_seq}."\n";
				print "  Namespace: ".$fn{namespace}."\n";
				print "    M: ".gmtime($fn{m_time})." Z\n";
				print "    A: ".gmtime($fn{a_time})." Z\n";
				print "    C: ".gmtime($fn{mft_m_time})." Z\n";
				print "    B: ".gmtime($fn{c_time})." Z\n";
			}
			elsif ($type == 0x80) {
				print "[\$DATA Attribute]\n";
				if ($name_len > 0) {
					my $i = substr($data,$ofs,$len);
					my $n = substr($i,$name_ofs,($name_len * 2));
					$n =~ s/\00//g;
					print "**ADS: ".$n."\n";
				}
				
				if ($res == 0) {
					print "[RESIDENT]\n";

				}
#---------------------------------------------------------------------
# Get file size
				my $file_size;
				if ($res == 0) {
					$file_size = unpack("V",substr($data,$ofs + 0x10,4));
				}
				else {
					my ($s1,$s2) = unpack("VV",substr($data,$ofs + 0x30,8));
					$file_size = convert64($s1,$s2);
				}
				print "File Size = ".$file_size." bytes\n";
				
#---------------------------------------------------------------------				
				
			}
			elsif ($type == 0xe0) {

				print "**Extended Attribute detected.\n";
			}
# This is where other attributes would get handled
			else{}		
			$ofs += $len;
		}
		print "\n";
#	$count++;
	}
	close(MFT);
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

#-----------------------------------------------------------
# parseRefNum() - takes 8 bytes, returns file record and 
#   sequence number pair
#
#-----------------------------------------------------------
sub parseRefNum {
	my $data = shift;
	my $rcd;
	
	my ($num1,$num2) = unpack("Vv",substr($data,0,6));
	
	if ($num2 != 0) {
		$num2 = ($num2 * 4294967296);
		$rcd  = $num1 + $num2;
	}
	else {
		$rcd = $num1;
	}
	my $seq = unpack("v",substr($data,6,2));
	return($rcd,$seq);
}

#-------------------------------------------------------------
# cleanStr()
# 'Clean up' Unicode strings; in short, 
#-------------------------------------------------------------
sub cleanStr {
	my $str = shift;
	my @list = split(//,$str);
	my @t;
	my $count = scalar(@list)/2;
	foreach my $i (0..$count) {
		push(@t,$list[$i*2]);
	}
	return join('',@t);
}

#-------------------------------------------------------------
# getTime()
# Translate FILETIME object (2 DWORDS) to Unix time, to be passed
# to gmtime() or localtime()
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

#-------------------------------------------------------------
# convert64()
# 
# borrowed from code provided by David Cowen
#-------------------------------------------------------------
sub convert64 {
	my $data1 = shift;
	my $data2 = shift;
	
	if ($data2 != 0) {
		$data2 = $data2 * 4294967296;
		return $data1 + $data2;
	}
	else {
		return $data1;
	}
}