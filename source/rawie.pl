#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# rawie.pl
# Read IE index.dat on a binary basis, locating URL and REDR
# records manually
#
# History
#  20140514 - updated to output in TLN format
#
# Refs:
#  https://googledrive.com/host/0B3fBvzttpiiSVm1MNkw5cU1mUG8/MSIE%20Cache%20File%20(index.dat)%20format.pdf
#  
#
# copyright 2014 QAR, LLC  H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
use strict;
use Time::Local;
use Getopt::Long;

my $VERSION = 20130215;

my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(file|f=s tln|t user|u=s server|s=s help|?|h));

if ($config{help} || ! %config) {
	_syntax();
	exit 1;
}

die "You must enter a filename\.\n" unless ($config{file});
die $config{file}." not found\." unless (-f $config{file});

my $ie = $config{file};
my $len = (stat($ie))[7];
my $data;

my $ofs = 0;
my $sz = 16;

open(FH,"<",$ie) || die "Could not open ".$ie." : $!\n";
binmode(FH);

while ($ofs < $len) {
	seek(FH,$ofs,0);
	read(FH,$data,$sz);
	
	my $sig = substr($data,0,4);
	
	if ($sig =~ m/^URL/) {
#		printf "Offset: 0x%08X\n",$ofs;
		my $tag = 1;
		my $buf = $data;
		my $sz_check = (unpack("V",substr($buf,4,4)) * 128);
		
		$ofs += $sz;
		while ($tag) {
			seek(FH,$ofs,0);
			read(FH,$data,$sz);
			my $hd = substr($data,0,4);
			if (($hd =~ m/^URL/ || $hd =~ m/^REDR/ || $hd =~ m/^LEAK/) || length($buf) == $sz_check) {
				$tag = 0;
			}
			else {
				$buf .= $data;
				$ofs += $sz;
			}
		}
		
		my $buf_len = length($buf);
		my $rec_sz  = unpack("V",substr($buf,4,4)) * 128;
		
		if ($buf_len < $rec_sz) {
			probe($buf) unless ($config{tln});
		}
		elsif ($buf_len == $rec_sz) {
			my %url = parseURLRecord($buf);
			if ($config{tln}) {
				print $url{lastaccessed}."|IE_URL|".$config{server}."|".$config{user}."|".$url{location}." last accessed [".$url{num_hits}."]\n";
			}
			else {
				print "URL: ".$url{location}."  Last Accessed: ".gmtime($url{lastaccessed})." Z \n";
			}
		}
		else {}

	}
	elsif ($sig =~ m/^REDR/) {
#		printf "Offset: 0x%08X\n",$ofs;
		my $tag = 1;
		my $buf = $data;
		$ofs += $sz;
		while ($tag) {
			seek(FH,$ofs,0);
			read(FH,$data,$sz);
			my $hd = substr($data,0,4);
			if ($hd =~ m/^URL/ || $hd =~ m/^REDR/ || $hd =~ m/^LEAK/) {
				$tag = 0;
			}
			else {
				$buf .= $data;
				$ofs += $sz;
			}
		}
		my $redr = parseREDRRecord($buf);
		if ($config{tln}) {
			
		}
		else {
			print "REDR: ".$redr."\n";
		}
	}
	else {}
	
	$ofs += $sz;
}
close(FH);


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
	$url{expiry} = convertDOSDate($t1,$t2);
	
	$url{location_ofs} = unpack("V",substr($data,52,4));
	$url{dir}          = unpack("C",substr($data,56,1));
	$url{filename_ofs} = unpack("V",substr($data,60,4));
	$url{flags}        = unpack("V",substr($data,64,4));
	$url{data_ofs}     = unpack("V",substr($data,68,4));
	$url{data_sz}      = unpack("V",substr($data,72,4));
	
	my ($t1,$t2) = unpack("vv",substr($data,80,4));
	$url{last_checked} = convertDOSDate($t1,$t2);
	
	$url{num_hits} = unpack("V",substr($data,84,4));
	
	my ($t1,$t2) = unpack("vv",substr($data,92,4));
	$url{last_sync} = convertDOSDate($t1,$t2);
	
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

sub _syntax {
print<< "EOT";
rawie v\.$VERSION [option]
Parse IE history index\.dat files (up to IE 9) on a binary basis

  -f file........Path to a file
  -t ............TLN output 
  -s server......Use with -t
  -u user........Use with -t                      
  -h ............Help (print this information)
  
Ex: C:\\>rawie -f index\.dat
    C:\\>rawie -f index\.dat -t -u user -s system

**All times printed as GMT/UTC

copyright 2014 Quantum Analytics Research, LLC
EOT
}