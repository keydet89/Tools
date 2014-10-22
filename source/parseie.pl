#! c:\perl\bin\perl.exe
#------------------------------------------------------------
# parseie.pl - parse IE index.dat file, based on format spec found
#   in the references
#
#
#
# History
#  20130215 - 'created'; the script has been in-process for some time,
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
use Time::Local;
use Getopt::Long;

my $VERSION = 20130215;

my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(file|f=s redr|r tln|t user|u=s server|s=s help|?|h));

if ($config{help} || ! %config) {
	_syntax();
	exit 1;
}

die "You must enter a filename\.\n" unless ($config{file});

my $file = $config{file};
my $data;

open(FH,"<",$file) || die "Could not open $file: $!\n";
binmode(FH);

seek(FH,0,0);
read(FH,$data,28);

if ($data =~ m/^Client UrlCache MMF/) {
	
}
else {
	die "Not a valid IE index file\.\n";
}

# Get offset to hash table
seek(FH,32,0);
read(FH,$data,4);
my $hash_ofs = unpack("V",$data);
#printf "Offset: 0x%x\n",$hash_ofs;

# Get the cache directory table, in a hash
seek(FH,72,0);
read(FH,$data,4);
my $num = unpack("V",$data);
seek(FH,72,0);
read(FH,$data, ($num * 12) + 4);
my %tab = parseDirTable($data);

# Process the hash table; note that there may be more
# than 1 hash table
my $tag = 1;
my @ofs = ();
while ($tag) {
	seek(FH,$hash_ofs,0);
	read(FH,$data,16);
#print "Signature: ".substr($data,0,4)."\n";
  my ($num_blocks,$next_ofs,$seq) = unpack("x4VVV",$data);
# parse the hash table entries
# assume only 1 block in the hash table
	my $data_size = ($num_blocks * 128) - 16;
	seek(FH,$hash_ofs + 16,0);
	read(FH,$data,$data_size);
	my @o = processHashTable($data);
	push(@ofs,@o);
	
	if ($next_ofs == 0) {
		$tag = 0;
	}
	else {
		$hash_ofs = $next_ofs;
	}
}

foreach my $o (sort {$a <=> $b} @ofs) {
	seek(FH,$o,0);
	read(FH,$data,8);
	my $size = unpack("V",substr($data,4,8));
	$size = ($size * 128);
	my $hdr = substr($data,0,4);
	
#	printf $hdr."|0x%x\n",$o;
	
	if ($hdr =~ m/^URL/) {
		seek(FH,$o,0);
		read(FH,$data,$size);
		my %u = parseURLRecord($data);
		
		my $filepath;
		if (exists $tab{$u{dir}}) {
			$filepath = $tab{$u{dir}}{name}."/".$u{filename};
		}
		else {
			$filepath = $u{filename};
		}
		
		if ($config{tln}) {
			my $desc = $u{request}." - ".$u{location};
			print $u{lastaccessed}."|IE_URL|".$config{server}."|".$config{user}."|".$desc."\n";
		}
		else {
# Format: URL, last accessed time, request, Location, File path, data (response string)			
			print "URL|".gmtime($u{lastaccessed})."|".$u{request}."|".$u{location}."|".$filepath."|".$u{data}."\n";
		}
	}
	elsif ($hdr =~ m/^REDR/) {
		if ($config{redr} && !$config{tln}) {
			seek(FH,$o,0);
			read(FH,$data,$size);
			my $r = parseREDRRecord($data);
			print "REDR|".$r."\n";
		}
	}
	elsif ($hdr =~ m/^LEAK/) {
		
#		printf "LEAK Record found at offset 0x%x\n",$o;
		
	}
	else {}
}

close(FH);

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

#-----------------------------------------------------------
# processHashTable()
# 
#-----------------------------------------------------------
sub processHashTable {
	my $data = shift;
	my @offsets = ();
	
	my $num = length($data)/8;
	foreach my $r (0..($num - 1)) {
		my ($hash,$ofs) = unpack("VV",substr($data,8 * $r,8));
		if ($hash == $ofs) {
# unused			
		}
		else {
			if ($hash == 0x1) {
# Invalid record				
			}
			else {
				push(@offsets,$ofs);
			}
		}
	}
	return @offsets;
}

#-----------------------------------------------------------
# parseURLRecord()
# 
#-----------------------------------------------------------
sub parseURLRecord {
	my $data = shift;
	my %url = ();
	$url{sig} = substr($data,0,4);
	my ($t1,$t2) = unpack("VV",substr($data,8,8));
	
	$url{lastmodified} = getTime($t1,$t2);
	my ($t1,$t2) = unpack("VV",substr($data,0x10,8));
	$url{lastaccessed} = getTime($t1,$t2);
	
	my ($t1,$t2) = unpack("vv",substr($data,0x18,4));
#	$url{expiry} = convertDOSDate($t1,$t2);
	
	$url{location_ofs} = unpack("V",substr($data,52,4));
	$url{dir}          = unpack("C",substr($data,56,1));
	$url{filename_ofs} = unpack("V",substr($data,60,4));
	$url{flags}        = unpack("V",substr($data,64,4));
	$url{data_ofs}     = unpack("V",substr($data,68,4));
	$url{data_sz}      = unpack("V",substr($data,72,4));
	
	my ($t1,$t2) = unpack("vv",substr($data,80,4));
#	$url{last_checked} = convertDOSDate($t1,$t2);
	
	my ($t1,$t2) = unpack("vv",substr($data,92,4));
#	$url{last_sync} = convertDOSDate($t1,$t2);
	
	if ($url{flags} & 0x1000) {
		$url{request} = "POST";
	}
	else {
		$url{request} = "GET";
	}
	
	$url{location} = getString($url{location_ofs},$data) unless ($url{location_ofs} == 0);
	$url{filename} = getString($url{filename_ofs},$data) unless ($url{filename_ofs} == 0);
	
	if (($url{data_ofs} == 0) || ($url{data_sz} == 0)) {
		
	}
	else {
		$url{data} = substr($data,$url{data_ofs},$url{data_sz});
		$url{data} =~ s/\r\n/ /g;
	}
	
	return %url;
}
#-----------------------------------------------------------
# parseREDRRecord()
# 
#-----------------------------------------------------------
sub parseREDRRecord {
	my $data = shift;
	my $len = length($data);
	my $str = (split(/\00/, substr($data,16,$len),2))[0];
	return $str;
}

#-----------------------------------------------------------
# getString()
# Given binary data and an offset, returns a null-terminated
# ASCII string
#-----------------------------------------------------------
sub getString {
	my $ofs = shift;
	my $data = shift;
	my $str = "";
	my $cnt = 0;
	my $tag = 1;
	while ($tag) {
		my $s = substr($data,$ofs + $cnt,1);
		if ($s =~ m/\00/) {
			$tag = 0;
		}
		else {
			$str .= $s;
			++$cnt;
		}
	}
	return $str;
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
	my $tag = 1;
	my $cnt = 0;
	my @display = ();
	
	my $loop = $len/16;
	$loop++ if ($len%16);
	
	foreach my $cnt (0..($loop - 1)) {
#	while ($tag) {
		my $left = $len - ($cnt * 16);
		
		my $n;
		($left < 16) ? ($n = $left) : ($n = 16);

		my $seg = substr($data,$cnt * 16,$n);
		my @str1 = split(//,unpack("H*",$seg));

		my @s3;
		my $str = "";

		foreach my $i (0..($n - 1)) {
			$s3[$i] = $str1[$i * 2].$str1[($i * 2) + 1];
			
			if (hex($s3[$i]) > 0x1f && hex($s3[$i]) < 0x7f) {
				$str .= chr(hex($s3[$i]));
			}
			else {
				$str .= "\.";
			}
		}
		my $h = join(' ',@s3);
#		::rptMsg(sprintf "0x%08x: %-47s  ".$str,($cnt * 16),$h);
		$display[$cnt] = sprintf "0x%08x: %-47s  ".$str,($cnt * 16),$h;
	}
	return @display;
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

#-----------------------------------------------------------
# convertDOSDate()
# subroutine to convert 4 bytes of binary data into a human-
# readable format.  Returns both a string and a Unix-epoch
# time.
#-----------------------------------------------------------
sub convertDOSDate {
	my $date = shift;
	my $time = shift;
	
	if ($date == 0x00 || $time == 0x00){
		return (0);
	}
	else {
		my $sec = ($time & 0x1f) * 2;
		$sec = "0".$sec if (length($sec) == 1);
		if ($sec == 60) {$sec = 59};
		my $min = ($time & 0x7e0) >> 5;
		$min = "0".$min if (length($min) == 1);
		my $hr  = ($time & 0xF800) >> 11;
		$hr = "0".$hr if (length($hr) == 1);
		my $day = ($date & 0x1f);
		$day = "0".$day if (length($day) == 1);
		my $mon = ($date & 0x1e0) >> 5;
		$mon = "0".$mon if (length($mon) == 1);
		my $yr  = (($date & 0xfe00) >> 9) + 1980;
		my $gm = timegm($sec,$min,$hr,$day,($mon - 1),$yr);
    return ($gm);
#    return ("$yr-$mon-$day $hr:$min:$sec");
#		return gmtime(timegm($sec,$min,$hr,$day,($mon - 1),$yr));
	}
}

sub _syntax {
print<< "EOT";
parseie v\.$VERSION [option]
Parse IE history index\.dat files (up to IE 9)
Default output is pipe-delimited

  -f file........Path to a file
  -r ............Include REDR records
  -t ............TLN output (includes heuristics)
  -s server......Use with -t
  -u user........Use with -t                      
  -h ............Help (print this information)
  
Ex: C:\\>parseie -f index\.dat
    C:\\>parseie -f index\.dat -t -u user -s system

**All times printed as GMT/UTC

copyright 2013 Quantum Analytics Research, LLC
EOT
}