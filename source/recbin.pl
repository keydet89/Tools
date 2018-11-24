#! c:\perl\bin\perl.exe
#------------------------------------------------------
# recbin.pl
# Perl script to parse the contents of the INFO2/$I files from
#   the Recycle Bin; can output .tln format
#
# Ref:
#  https://df-stream.com/2016/04/fun-with-recycle-bin-i-files-windows-10/
#
# usage: see usage()
#
# Change history:
#   20181124 - added size output for INFO2
#   20181120 - updated
#   20120509 - Added support for detecting and parsing Vista/Win7 
#              Recycle Bin $I..... files
#		20090608 - TLN output to STDOUT, rather than file
#
# copyright 2018 Quantum Analytics Research, LLC
# Author: H. Carvey keydet89@yahoo.com
#------------------------------------------------------
use strict;
use Getopt::Long;

my %config;
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config,qw(file|f=s csv|c tln|t system|s=s user|u=s help|?|h));

if ($config{help} || !%config) {
	usage();
	exit 1;
}
my $file;

if (! $config{file}) {
	print "Filename required.\n";
	exit 1;
}
else {
	$file = $config{file};
}

my @list = split(/\\/,$file);
my $name = $list[(scalar(@list) - 1)];
if (uc($name) eq "INFO2") {
#	print "XP Recycle Bin file.\n";
	parseINFO2($file);
}
elsif (uc($name) =~ m/^\$I/) {
	my $ver = checkHeader($file);
	if ($ver == 1) {
		parseWin7($file);
	} 
	elsif ($ver == 2) {
		parseWin10($file);
	}
	else {
		print "Unknown version for ".$file.": ".$ver."\n";
	}
}
else { 
# Unknown	
}


sub parseINFO2 {
	my $file = shift;
#---------------------------------------------------------
# some GLOBAL variables
#---------------------------------------------------------
	my $data;
	my $ofs = 0;

	open(FH,"<",$file);
	binmode(FH);
	seek(FH,$ofs,0);
	read(FH,$data,16);
	my @hdr = unpack("V4",$data);
	$ofs += 16;

	while (! eof(FH)) {
		seek(FH,$ofs,0);
		my $bytes = read(FH,$data,$hdr[3]);
# Process the record	
		my %rec = parseRecord($data);
		next if ($rec{num} == 0 && $rec{drive} == 0);
		my $t = gmtime($rec{del_time});
		if ($config{csv}) {
			print $rec{num}.",".$t.", ".$rec{u_name}." size: ".$rec{size}." bytes\n";
		}
		elsif ($config{tln}) {
			my $str = $rec{del_time}."|RECBIN|".$config{system}."|".$config{user}."|DELETED - ".$rec{u_name}." [".$rec{size}."] bytes";
			print $str."\n";
		}
		else {
			printf "%-4d %-28s %-48s  size: ".$rec{size}." bytes\n",$rec{num},$t,$rec{u_name};
		}
	
		$ofs += $hdr[3];
	}
close(FH);
}

#---------------------------------------------------------
# parseRecord()
# Parses an INFO2 record
#---------------------------------------------------------
sub parseRecord {
	my $rec = shift;
	my $RECNUM_OFS = 264;
	my $DRIVE_OFS  = 268;
	my $TIME_OFS   = 272;
	my $SIZE_OFS   = 280;
	my %record = ();
	$record{a_name} = substr($rec,4,260);
	$record{a_name} =~ s/\00//g;
	$record{num}   = unpack("V",substr($rec,$RECNUM_OFS,4));
	$record{drive} = unpack("V",substr($rec,$DRIVE_OFS,4));
	my ($t1,$t2)   = unpack("VV",substr($rec,$TIME_OFS,8));
	
	$record{del_time} = getTime($t1,$t2);
	$record{size}  = unpack("V",substr($rec,$SIZE_OFS,4));
	$record{u_name} = substr($rec,$SIZE_OFS + 4,516);
	$record{u_name} =~ s/\00//g;
	return %record;
}

sub checkHeader {
	my $file = shift;
	my $data;
	open(FH,"<",$file);
	binmode(FH);
	seek(FH,0,0);
	read(FH,$data,8);
	my ($t0,$t1) = unpack("VV",$data);
	close(FH);
	return $t0;
}

#---------------------------------------------------------
# parseWin7()
# Parses a Vista/Win7 Recycle Bin $I.... file
#---------------------------------------------------------
sub parseWin7 {
	my $file = shift;
	my $size = (stat($file))[7];
	my $data;
	open(FH,"<",$file);
	binmode(FH);
	seek(FH,0,0);
	read(FH,$data,$size);
	close(FH);
	
	my @szs = unpack("VV",substr($data,0x08,8));
	my $sz = c64($szs[0],$szs[1]);
	
	my $t = getTime(unpack"VV",substr($data,0x10,8));
	my $name = substr($data,0x18,($size - 0x18));
	$name =~ s/\00//g;

	if ($config{csv}) {
		print $name.", size: ".$sz.",".$t."\n";
	}
	elsif ($config{tln}) {
		print $t."|RECBIN|".$config{system}."|".$config{user}."|DEL - [".$sz."] ".$name."\n";
	}
	else {
		print $name." [".$sz." bytes] deleted on ".gmtime($t)." Z\n";
	}
}

#---------------------------------------------------------
# parseWin10()
# Parses a Win10 Recycle Bin $I.... file
#---------------------------------------------------------
sub parseWin10 {
	my $file = shift;
	my $size = (stat($file))[7];
	my $data;
	open(FH,"<",$file);
	binmode(FH);
	seek(FH,0,0);
	read(FH,$data,$size);
	close(FH);
	
	my @szs = unpack("VV",substr($data,0x08,8));
	my $sz = c64($szs[0],$szs[1]);
	
	my $t = getTime(unpack"VV",substr($data,0x10,8));
	
	my $name_sz = unpack("V",substr($data,0x18,4));
	my $name = substr($data,0x1c,$name_sz * 2);
	$name =~ s/\00//g;

	if ($config{csv}) {
		print $name.", size: ".$sz.",".$t."\n";
	}
	elsif ($config{tln}) {
		print $t."|RECBIN|".$config{system}."|".$config{user}."|DEL - [".$sz."] ".$name."\n";
	}
	else {
		print $name." [".$sz." bytes] deleted on ".gmtime($t)." Z\n";
	}
}

#---------------------------------------------------------
# getTime()
# Get Unix-style date/time from FILETIME object
# Input : 8 byte FILETIME object
# Output: Unix-style date/time
#---------------------------------------------------------
sub getTime {
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

#---------------------------------------------------------
#
#---------------------------------------------------------
sub c64 {
	my $num1 = shift;
	my $num2 = shift;
	if ($num2 != 0) {
		$num2 = ($num2 * 4294967296);
		return $num1 + $num2;
	}
	else {
		return $num1;
	}
}

#---------------------------------------------------------
# usage()
#---------------------------------------------------------
sub usage {
	print<< "EOT";
Recbin [options]
Parse Windows Recycle Bin INFO2 & \$Ixxxxx files in binary mode, translating 
the information listed; sends data to STDOUT, can also generate timeline data

  -f file..................path to XP INFO2 file or Win7/10 \$I file
  -c ......................output in csv format to STDOUT
  -t ......................timeline format output to STDOUT
  -s systemname............add system name to appropriate field in tln file
  -u user..................add user (or SID) to appropriate field in tln file
  -h.......................Help (print this information)
  
Ex: C:\\>recbin -f INFO2 
    C:\\>recbin -f d:\\cases\\\$IJ36543\.exe -t
  
copyright 2018 Quantum Analytics Research, LLC
EOT
}