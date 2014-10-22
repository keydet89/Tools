#! c:\perl\bin\perl.exe
#---------------------------------------------------------------------
# idxparse.pl - Script to parse Java deployment cache *.idx files
# Parse Java deployment cache index (*.idx) files
#
# History
#  20130212 - updated to cover an additional variant of v.605 idx files
#
# WinXP Path:
#  C:\Documents and Settings\user\Application Data\Sun\Java\Deployment\cache\6.0
#
# Win7 Path:
#  C:\Users\user\AppData\LocalLow\Sun\Java\Deployment\cache\6.0
#
# copyright 2013 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#---------------------------------------------------------------------
use strict;
use Math::BigInt;
use Time::Local;
use Getopt::Long;

my $VERSION = 20130212;

my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(file|f=s dir|d=s csv|c tln|t user|u=s server|s=s help|?|h));

if ($config{help} || ! %config) {
	_syntax();
	exit 1;
}

my @files;
my $data;

if (-d $config{dir}) {
# for this code to work, the path should be similar to:
# C:\Users\user\AppData\LocalLow\Sun\Java\Deployment\cache\6.0\	
	$config{dir} = $config{dir}."\\" unless ($config{dir} =~ m/\\$/);
	my @d;
	opendir(DIR,$config{dir});
	@d = readdir(DIR);
	close(DIR);
	my @subdirs;
	
	foreach (@d) {
		next if ($_ =~ m/^\./);
		my $path = $config{dir}.$_;
		if (-d $path && $_ =~ m/^\d/) {
			push(@subdirs,$path);
		}
	}
	
	foreach my $sd (@subdirs) {
		$sd = $sd."\\" unless ($sd =~ m/\\$/);
		opendir(DIR,$sd);
		my @idx = grep {/\.idx$/} readdir(DIR);
		closedir(DIR);
		foreach my $i (@idx) {
			push(@files,$sd.$i);
		}
	}
}

push(@files,$config{file}) if ($config{file});

foreach my $file (@files) {
	my %idx = ();
	$idx{file} = $file;
	
# Read header
	my %hdr = parseHeader($file);
	my $offset;
	my $known;
	
	$idx{magic} = $hdr{cacheversion};
	
	if ($hdr{cacheversion} == 602) {
		$known = 1;
		$idx{url} = $hdr{url};
		$idx{len} = $hdr{contentlength};
		$idx{lastmod} = $hdr{lastmod};
		
		$offset = $hdr{offset};
		open(FH,"<",$file);
		binmode(FH);
		seek(FH,$offset,0);
		read(FH,$data,4);
		close(FH);
		$idx{type} = unpack("N",$data);
	}
	elsif ($hdr{cacheversion} == 603 || $hdr{cacheversion} == 604) {
		$known = 1;
		$offset = 0x80;
		
		open(FH,"<",$file);
		binmode(FH);
		seek(FH,$offset,0);
#-----------------------------------------------------------	
# added 20130218	
		read(FH,$data,2);
		my $i = unpack("n",$data);
		if ($i == 0) {
			seek(FH,$offset,0);
			read(FH,$data,4);
			my $l = unpack("N",$data);
			$offset += 4;
			seek(FH,$offset,0);
			read(FH,$data,$l);
			$idx{url} = $data;
			$offset += $l;
		}
		else {
			$offset += 2;
			seek(FH,$offset,0);
			read(FH,$data,$i);
			$idx{huh} = $data;
			$offset += $i;
			
			seek(FH,$offset,0);
			read(FH,$data,2);
			my $a = unpack("n",$data);
			$offset += 2;
			seek(FH,$offset,0);
			read(FH,$data,$a);
			$idx{url} = $data;
			$offset += $a;
		}
#-----------------------------------------------------------		
		seek(FH,$offset,0);
		read(FH,$data,4);
		my $l = unpack("N",$data);

		$offset += 4;
		seek(FH,$offset,0);
		read(FH,$data,$l);
		$idx{IP} = $data;

		$offset += $l;
		seek(FH,$offset,0);
		read(FH,$data,4);
		close(FH);
		$idx{type} = unpack("N",$data);
		$idx{len} = $hdr{contentlength};
		$idx{lastmod} = $hdr{lastmod};
#printf "Type: ".$type." (0x%04x)\n",$type;
	}
	elsif ($hdr{cacheversion} == 605) {
		$known = 1;
		$offset = 0x80;
		open(FH,"<",$file);
		binmode(FH);
		seek(FH,$offset,0);
		
#-----------------------------------------------------------		
		read(FH,$data,2);
		my $i = unpack("n",$data);
		if ($i == 0) {
			seek(FH,$offset,0);
			read(FH,$data,4);
			my $l = unpack("N",$data);
			$offset += 4;
			seek(FH,$offset,0);
			read(FH,$data,$l);
			$idx{url} = $data;
			$offset += $l;
		}
		else {
			$offset += 2;
			seek(FH,$offset,0);
			read(FH,$data,$i);
			$idx{huh} = $data;
			$offset += $i;
			
			seek(FH,$offset,0);
			read(FH,$data,2);
			my $a = unpack("n",$data);
			$offset += 2;
			seek(FH,$offset,0);
			read(FH,$data,$a);
			$idx{url} = $data;
			$offset += $a;
		}
#-----------------------------------------------------------		
		
		seek(FH,$offset,0);
		read(FH,$data,4);
		my $l = unpack("N",$data);

		$offset += 4;
		seek(FH,$offset,0);
		read(FH,$data,$l);
		$idx{IP} = $data;

		$offset += $l;
		seek(FH,$offset,0);
		read(FH,$data,4);
		close(FH);
		$idx{type} = unpack("N",$data);
		$idx{len} = $hdr{contentlength};
		$idx{lastmod} = $hdr{lastmod};
	}
	else {
# unknown "magic number"
		printf "Unknown 'magic number': 0x%x\n",$idx{magic};
		$known = 0;		
	}
	close(FH);
	
	my %items;
	if ($known) {
		$offset += 4;
		%items = parseElements1($idx{file},$offset,$idx{type});
	}
	
	foreach (0..(scalar(keys %items) - 1)) {
		if (grep(/HTTP\/1\.1 200 OK/,$items{$_})) {
			$idx{httpsuccess} = 1;
		}
		
		if ($items{$_} =~ m/^server:/) {
			$idx{server} = (split(/:/,$items{$_},2))[1];
			$idx{server} =~ s/^\s//;
		}
# determine epoch value for "date:" field for heuristics		
		if ($items{$_} =~ m/^date:/) {
			my $datefield = (split(/:/,$items{$_},2))[1];
			$datefield =~ s/^\s//;
			$idx{dateepoch} = parseDateField($datefield);
		}
	}
	
	if ($config{csv}) {
		my $lastmod;
		if ($idx{lastmod} == 0) {
			$lastmod = 0;
		}
		else {
			$lastmod = gmtime($idx{lastmod})." GMT";
		}
		$lastmod =~ s/,//g;
		print $idx{file}.",".$idx{url}.",".$idx{IP}.",".$idx{len}.",".$lastmod.",";
		my @i;
		foreach (0..(scalar(keys %items) - 1)) {
			$items{$_} =~ s/,//g;
			push(@i,$items{$_});
		}
		print join(',',@i);
		print "\n";
	}
	elsif ($config{tln}) {
# build the description field		
		my $desc;
		if ($idx{magic} == 602) {
			$desc = $idx{url};
			if ($idx{httpsuccess}) {
				$desc .= " [".$idx{server}."]";
			}
		}
		elsif ($idx{magic} == 603 || $idx{magic} == 604 || $idx{magic} == 605) {
			$desc = $idx{url};
			if ($idx{httpsuccess}) {
				$desc .= " [".$idx{IP}."/".$idx{server}."]";
			}
		}
		else {
			
		}
		
		if ($idx{httpsuccess}) {
			print $idx{dateepoch}."|JAVA_IDX|".$config{server}."|".$config{user}."|malware|".$desc."\n";
		}
	
	}
	else {
		print "File: ".$idx{file}."\n";
		print "URL : ".$idx{url}."\n";
		print "IP  : ".$idx{IP}."\n" if (exists $idx{IP});
		print "content-length: ".$idx{len}."\n";
		print "last-modified : ".gmtime($idx{lastmod})." GMT\n" if ($idx{lastmod} > 0);
		
		if ($known) {
			print "\n";
			print "Server Response:\n";
			print "-" x 30,"\n";
			foreach (0..(scalar(keys %items) - 1)) {
				print $items{$_}."\n";
			}
			print "\n";
		}
	}
}

sub parseHeader {
	my $file = shift;
	my $data;
	my %hdr;
	
	open(FH,"<",$file);
	binmode(FH);
	seek(FH,0,0);
	read(FH,$data,6);
	
	$hdr{cacheversion} = unpack("N",substr($data,2,4));
	
	my $header_len; 
	if ($hdr{cacheversion} == 602) {
		$header_len = 0x1d;
	}
	elsif ($hdr{cacheversion} == 603 || $hdr{cacheversion} == 604 || $hdr{cacheversion} == 605) {
		$header_len = 0x80;
	}
	else {}
	seek(FH,0,0);
	read(FH,$data,$header_len);
	close(FH);
# $data buffer now contains the header of the file
	if ($hdr{cacheversion} == 602) {
		$hdr{contentlength} = unpack("N",substr($data,9,4));
		my $mod = "0x".unpack("H*",substr($data,0xd,8));
		$hdr{lastmod} = (Math::BigInt->new($mod))/1000;
		$hdr{valid} = (Math::BigInt->new("0x".unpack("H*",substr($data,0x15,8)))/1000);
		
		my $offset = 0x1d;
# Get the version string, if there is one		
		open(FH,"<",$file);
		binmode(FH);
		seek(FH,$offset,0);
		read(FH,$data,2);
		my $sz = unpack("n",$data);
		
		$offset += 2;
		seek(FH,$offset,0);
		read(FH,$data,$sz);
		$hdr{versionstr} = $data;
# Get the URL		
		$offset += $sz;
		seek(FH,$offset,0);
		read(FH,$data,2);
		my $len = unpack("n",$data);
		
		$offset += 2;
		seek(FH,$offset,0);
		read(FH,$data,$len);
		$offset += $len;
		$hdr{url} = $data;
		
		seek(FH,$offset,0);
		read(FH,$data,2);
		my $sz = unpack("n",$data);
		$offset += 2;
		
		seek(FH,$offset,0);
		read(FH,$data,$sz);
		$hdr{namespace} = $data;
		$offset += $sz;
		close(FH);
		
		$hdr{offset} = $offset;
	}
	elsif ($hdr{cacheversion} == 603 || $hdr{cacheversion} == 604) {
		$hdr{contentlength} = unpack("N",substr($data,9,4));
		$hdr{lastmod} = (Math::BigInt->new("0x".unpack("H*",substr($data,0xd,8))))/1000;
		$hdr{expiry} = (Math::BigInt->new("0x".unpack("H*",substr($data,0x15,8)))/1000);
		$hdr{valid} = (Math::BigInt->new("0x".unpack("H*",substr($data,0x1d,8)))/1000);
		
		$hdr{sec2len} = unpack("N",substr($data,38,4));
		$hdr{sec3len} = unpack("N",substr($data,42,4));
		$hdr{sec4len} = unpack("N",substr($data,46,4));
		$hdr{sec5len} = unpack("N",substr($data,50,4));
		
		$hdr{blacklist} = (Math::BigInt->new("0x".unpack("H*",substr($data,0x36,8))))/1000;
		$hdr{certexpiry} = (Math::BigInt->new("0x".unpack("H*",substr($data,0x3e,8))))/1000;
	}
	elsif ($hdr{cacheversion} == 605) {
		$hdr{contentlength} = unpack("N",substr($data,7,4));
		$hdr{lastmod} = (Math::BigInt->new("0x".unpack("H*",substr($data,0xb,8))))/1000;
		$hdr{expiry} = (Math::BigInt->new("0x".unpack("H*",substr($data,0x13,8)))/1000);
		$hdr{valid} = (Math::BigInt->new("0x".unpack("H*",substr($data,0x1b,8)))/1000);
		
		$hdr{sec2len} = unpack("N",substr($data,36,4));
		$hdr{sec3len} = unpack("N",substr($data,40,4));
		$hdr{sec4len} = unpack("N",substr($data,44,4));
		$hdr{sec5len} = unpack("N",substr($data,48,4));
		
		$hdr{blacklist} = (Math::BigInt->new("0x".unpack("H*",substr($data,0x34,8))))/1000;
		$hdr{certexpiry} = (Math::BigInt->new("0x".unpack("H*",substr($data,0x3c,8))))/1000;
	}
	else {
# unknown magic number		
		
	}
	return %hdr;
}

sub parseElements1 {
	my $file = shift;
	my $offset = shift;
	my $type = shift;
	my $num = ($type * 2) - 1;
	
	my %items = ();
	my @temp = ();
	my $data;
	
	open(FH,"<",$file);
	binmode(FH);
	foreach my $n (0..$num) {
		seek(FH,$offset,0);
		read(FH,$data,2);
		my $l = unpack("n",$data);
		
		$offset += 2;
		seek(FH,$offset,0);
		read(FH,$data,$l);
		$temp[$n] = $data;
		$offset += $l;
	}
	close(FH);
	
	foreach my $i (0..($type - 1)) {
		my $n = $i * 2;
		$items{$i} = $temp[$n].": ".$temp[$n + 1];
	}

	return %items;
}

#----------------------------------------------------------
# parseDateField()
# Takes the "date:" field from the server response (if there is one)
# and returns a Unix epoch time
#----------------------------------------------------------
sub parseDateField {
	my $date = shift;
	
	my %months = ("Jan" => 0,
	           "Feb" => 1,
	           "Mar" => 2,
	           "Apr" => 3,
	           "May" => 4,
	           "Jun" => 5,
	           "Jul" => 6,
	           "Aug" => 7,
	           "Sep" => 8,
	           "Oct" => 9,
	           "Nov" => 10,
	           "Dec" => 11);
	
	my ($day,$month,$year,$time) = (split(/\s/,$date))[1,2,3,4];
	my ($hour,$min,$sec) = split(/:/,$time,3);
	my $mon;
	foreach (keys %months) {
		if ($month =~ m/^$_/) {
			$mon = $months{$_};
		}
	}
	return timegm($sec,$min,$hour,$day,$mon,$year);
}

sub _syntax {
print<< "EOT";
idxparse v\.$VERSION [option]
Parse Java deployment cache *\.idx files

  -f file........Path to a file
  -d dir.........Directory (see example below)
  -c ............CSV output 
  -t ............TLN output 
  -s server......Use with -t
  -u user........Use with -t                      
  -h ............Help (print this information)
  
Ex: C:\\>idx -f file.idx
    C:\\>idx -d c:\users\user\appdata\locallow\sun\java\deployment\cache\6.0

**All times printed as GMT/UTC

copyright 2013 Quantum Analytics Research, LLC
EOT
}