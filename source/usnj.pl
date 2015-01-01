#!C:\perl\bin\perl.exe 
#------------------------------------------------------------
# usnj.pl
# Parse NTFS UsrJrnl entries (v2 only...see Ref below)
#
# You can find and extract this file via FTK Imager: 
#  [root]/$Extend/$UsnJrnl:$J
#
# History:
#    20140418 - updated code to parse file and parent ref numbers
#               (use this to tie to MFT)
#
# Ref:
#    v2: http://msdn.microsoft.com/en-us/library/aa365722(v=vs.85).aspx
#    v3: http://msdn.microsoft.com/en-us/library/hh802708(v=vs.85).aspx
#
# Example of other code:
#    http://code.google.com/p/parser-usnjrnl/
#    
#
# copyright 2014 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#------------------------------------------------------------
use strict;
use Getopt::Long;

my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(file|f=s csv|c tln|t server|s=s help|?|h));

if ($config{help} || ! %config) {
	_syntax();
	exit 1;
}
my $file = $config{file};
my $size = (stat($file))[7];
my $offset = 0;
my $data;
my $fh;

open($fh,"<",$file) || die "Could not open $file: $!\n";
binmode($fh);
$offset = movePtr($offset,512);
$offset = movePtr($offset,4);

while ($offset < $size) {
	seek($fh,$offset,0);
	read($fh,$data,4);

	my $sz = unpack("V",$data);
	if ($sz == 0) {
		$offset = movePtr($offset,4);
	}
	else {
		seek($fh,$offset,0);
		read($fh,$data,$sz);

		my $ver = unpack("v",substr($data,4,2));
#		print "version = ".$ver."\n";
		my %u;
		if ($ver == 2) {
			%u = parseV2($data);
			if ($config{csv}) {
				print gmtime($u{timestamp}).",".$u{name}.",".$u{reason}."\n";
			}
			elsif ($config{tln}) {
				printf $u{timestamp}."|USNJ|".$config{server}."||".$u{name}.": ".$u{reason}."  FileRef: ".$u{fileref}."  ParentRef: ".$u{parentref}."\n";
			}
			else {
				print "Name: ".$u{name}."  FileRef: ".$u{fileref}."  ParentRef: ".$u{parentref}."\n";
				printf "Reason = ".$u{reason}." (0x%x)\n",$u{reason_code};
				print "\n";
			}
			
		}
		elsif ($ver == 3) {
			print "Version 3 parsing not implemented in this version.\n";
		}
		else {
			print "Unknown Version: ".$ver."\n";
		}
		$offset += $sz;
	}
}

close(FH);

sub parseV2 {
	my $data = shift;
	my %v = ();
	
	my %reason = (0x00080000 => "Basic_Info_Change",
	              0x80000000 => "Close",
	              0x00020000 => "Compression_Change",
	              0x00000002 => "Data_Extend",
	              0x00000001 => "Data_Overwrite",
	              0x00000004 => "Data_Truncation",
	              0x00000400 => "EA_Change",
	              0x00040000 => "Encryption_Change",
	              0x00000100 => "File_Create",
	              0x00000200 => "File_Delete",
	              0x00010000 => "Hard_Link_Change",
	              0x00004000 => "Indexable_Change",
	              0x00000020 => "Named_Data_Extend",
	              0x00000010 => "Named_Data_Overwrite",
	              0x00000040 => "Named_Data_Truncation",
	              0x00080000 => "Object_ID_Change",
	              0x00002000 => "Rename_New_Name",
	              0x00001000 => "Rename_Old_Name",
	              0x00100000 => "Reparse_Point_Change",
	              0x00000800 => "Security_Change",
	              0x00200000 => "Stream_Change");
	
	($v{major_version},$v{minor_version}) = unpack("vv",substr($data,4,4));
	
	my @fileref = unpack("Vvv",substr($data,8,8));
	$v{fileref} = num48($fileref[0],$fileref[1])."/".$fileref[2];
	
	my @parentref = unpack("Vvv",substr($data,16,8));
	$v{parentref} = num48($parentref[0],$parentref[1])."/".$parentref[2];
	
	my ($t1,$t2) = unpack("VV",substr($data, 0x20, 8));
	$v{timestamp} = getTime($t1,$t2);
	
	$v{reason_code} = unpack("V",substr($data,0x28,4));
	my @r;
	foreach (keys %reason) {
		push(@r,$reason{$_}) if ($v{reason_code} & $_);
	}
	$v{reason} = join(',',@r);
	
	$v{source_info} = unpack("V",substr($data,0x2c,4));
	
	($v{name_len},$v{name_ofs}) = unpack("vv",substr($data,0x38,4));
	
	$v{name} = substr($data,$v{name_ofs},$v{name_len});
	$v{name} =~ s/\00//g;
	
	return %v;
}

sub parseV3 {
	my $data = shift;
	my %v = ();
	
	return %v;
}

#-----------------------------------------------------------
# movePtr()
#
# Given an offset, move 4 bytes at a time until non-zero
# data is found.
#-----------------------------------------------------------
sub movePtr {
	my $ofs = shift;
	my $size = shift;
	my $data;
	my $tag = 1;
	while($tag) {
		seek($fh,$ofs,0);
		read($fh,$data,$size);
		my $str = unpack("B*",$data);
		if ($str == 0) {
			$ofs += $size;
		}
		else {
			$tag = 0;
		}
	}
	return $ofs;
}

#-------------------------------------------------------------
#
#-------------------------------------------------------------	
sub num48 ($$) {
	my $n1 = shift;
	my $n2 = shift;
	my $n;
	
	if ($n2 != 0) {
		$n2 = ($n2 * 16777216);
		$n = $n1 + $n2;
		return $n;
	}
	else {
		return $n1;
	}
}

#-------------------------------------------------------------
# getTime()
# Translate FILETIME object (2 DWORDS) to Unix time, to be passed
# to gmtime() or localtime()
#
# The code was borrowed from Andreas Schuster's excellent work
#-------------------------------------------------------------
sub getTime($$) {
	my $lo = $_[0];
	my $hi = $_[1];
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

sub _syntax {
print<< "EOT";
usnj [options]
Parse NTFS USN Change Journal log 

  -f file........USN Change Journal (full path)
  -c ............CSV output
  -t ............TLN output (use with -s)
  -s server......System name (use with -t)
  -h ............Help (print this information)
  
Ex: C:\\>usnj.pl -f <path> -c 
    C:\\>usnj.pl -f <path> -t -s server

**All times printed as GMT/UTC

copyright 2013 Quantum Analytics Research, LLC
EOT
}