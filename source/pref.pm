package pref;
$VERSION = 0.1;
#------------------------------------------------------
# pref.pm
# Perl module to parse Windows prefetch files
# 
# History:
#  20130926 - updated to support Win8
#
# Ref:
#  http://www.forensicswiki.org/wiki/Prefetch
#  http://www.invoke-ir.com/2013/09/whats-new-in-prefetch-for-windows-8.html
#
# copyright 2013 Quantum Analytics Research, LLC
# Author: H. Carvey keydet89@yahoo.com
#------------------------------------------------------
use strict;
use vars qw($VERSION @ISA @EXPORT_OK);
use Carp;

require Exporter;

@ISA         = qw(Exporter);
@EXPORT_OK   = qw(new);

my $self;				# self reference
my @runtimes = ();
my $data;

#---------------------------------------------------------------------
# new()
# Opens file in binary mode; blesses self, including file handle
# 
#---------------------------------------------------------------------      	    
sub new {
	$self = {};
	my $class = shift;
	$self->{file} = shift;
	
	if (open(FH,"<",$self->{file})) {
		binmode(FH);
		seek(FH,4,0);
		read(FH,$data,4);
		$self->{sig} = $data;
		getOffsets();
		return bless $self;
	}
}


sub getSig {
	return $self->{sig};
}

#---------------------------------------------------------
# getOffsets()
# 0x98  - XP
# 0xF0  - Vista/Win7
# 0x130 - Win8
#---------------------------------------------------------
sub getOffsets {
	if (open(FH,"<",$self->{file})) {
		binmode(FH);
		seek(FH,0,0);
		read(FH,$data,8);
		($self->{version},$self->{magic}) = unpack("VV",$data);

# get the hash
		seek(FH,0x4c,0);
		read(FH,$data,4);
		$self->{hash} = unpack("V",$data);

# Get module path info (offset, size)
		seek(FH,0x64,0);
		read(FH,$data,8);
		($self->{mod_ofs},$self->{mod_sz}) = unpack("VV",$data);		
		
# Get Volume Information Block offset		
		seek(FH,0x6c,0);
		read(FH,$data,4);
		$self->{vib_ofs} = unpack("V",$data);
		close(FH);
# XP		
		if ($self->{version} == 0x11) {
			$self->{time_offset} = 0x78;
			$self->{runcount_offset} = 0x90;
		}
# Vista/Win7		
		elsif ($self->{version} == 0x17) {
			$self->{time_offset} = 0x80;
			$self->{runcount_offset} = 0x98;
		}
# Win8		
		elsif ($self->{version} == 0x1A) {
# for Win8, there are actually 8 FILETIME time stamps listed starting
# at offset 0x80
			$self->{time_offset} = 0x80;
			$self->{runcount_offset} = 0xd0; 
		}
		else {
# place holder			
		}
	}
	else {
# unable to open file		
	}
}

#---------------------------------------------------------
# getVersion()
# 
#---------------------------------------------------------
sub getVersion {
	return $self->{version};
}

#---------------------------------------------------------
# getExeName()
# get EXE name from .pf files
#---------------------------------------------------------
sub getExeName {
	my $name;
	my $tag = 1;
	open(FH,"<",$self->{file});
	binmode(FH);
	seek(FH,0x10,0);
	while ($tag) {
		read(FH,$data,2);
		$tag = 0 if (unpack("v",$data) == 0);
		$name .= $data;
	}
	close(FH);
	$name =~ s/\00//g;
	return $name;
}

#---------------------------------------------------------
# getMetaData()
# get metadata from .pf files
#---------------------------------------------------------
sub getMetaData {
	my ($runcount,$runtime);
	my @tvals = ();
	
	open(FH,"<",$self->{file});
	binmode(FH);
# Windows 8 can have up to 8 times stored	
	if ($self->{version} == 0x1A) {
		foreach my $n (0..7) {
			seek(FH,$self->{time_offset} + ($n * 8),0);
			read(FH,$data,8);
			@tvals = unpack("VV",$data);
			
			if ($tvals[0] == 0 && $tvals[1] == 0) {
				
				
			}
			else {
				$runtimes[$n] = getTime($tvals[0],$tvals[1]);
			}	
		}
		$runtime = $runtimes[0];
	}
	else {
		seek(FH,$self->{time_offset},0);
		read(FH,$data,8);
		@tvals = unpack("VV",$data);
		$runtime = getTime($tvals[0],$tvals[1]);
	}

	seek(FH,$self->{runcount_offset},0);
	read(FH,$data,4);
	$runcount = unpack("V",$data);
	
	close(FH);
	return ($runcount,$runtime);
}

#---------------------------------------------------------
# getRuntimes()
# Win8 .pf files can have up to 8 runtimes, with the first
# one being the most recent
#---------------------------------------------------------
sub getRuntimes {
	return @runtimes;
}

#---------------------------------------------------------
# getTime()
# Get Unix-style date/time from FILETIME object
# Input : 8 byte FILETIME object
# Output: Unix-style date/time
# Thanks goes to Andreas Schuster for the below code, which he
# included in his ptfinder.pl
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
# getFilepaths()
# Get list of Unicode file paths embedded in the .pf file
#---------------------------------------------------------
sub getPaths {
	my ($ofs,$size);
	my @paths;
	
	open(FH,"<",$self->{file});
	binmode(FH);

	seek(FH,$self->{mod_ofs},0);
	read(FH,$data,$self->{mod_sz});
	close(FH);

	my @list = split(/\00\00/,$data);
#print "Strings = ".scalar(@list)."\n";
	foreach my $str (@list) {
		$str =~ s/\00//g;
		next if ($str eq "");
		push(@paths,$str);
	}
	return @paths;
}

#---------------------------------------------------------
# getVibData()
# Get volume information block data embedded in the .pf file
#---------------------------------------------------------
sub getVibData {
	my %vib_data;
	
	open(FH,"<",$self->{file});
	binmode(FH);
#	print "File: ".$self->{file}."\n";
#	printf "VIB Offset = 0x%x\n",$self->{vib_ofs};
	seek(FH,$self->{vib_ofs},0);
	read(FH,$data,20);
#	my ($path_ofs,$path_ln,$time0,$time1,$sn) = unpack("V5",$data);
	my @vib = unpack("V5",$data);
	seek(FH,$self->{vib_ofs} + $vib[0],0);
	read(FH,$data,$vib[1] * 2);
	$data =~ s/\00//g;
	$vib_data{volumepath} = $data;
	$vib_data{creationdate} = getTime($vib[2],$vib[3]);
	
	my $str = uc(sprintf "%x",$vib[4]);
#	$vib_data{volumeserial} = substr($str,0,4)."-".substr($str,4,4);
	$vib_data{volumeserial} = join('-',unpack("(A4)*",$str));
	close(FH);
	return %vib_data;
}

1;