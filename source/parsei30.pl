#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# parsei30.pl
# 
# All page references in File System Forensic Analysis
#
#
# copyright 2010 Quantum Analytics Research, LLC
#-----------------------------------------------------------
use strict;
#use Encode;

#my $file = "\$I30";
my $file = shift || die "You must enter a filename.\n";
die $file." not found.\n" unless (-e $file);

my $data;
open(FH,"<",$file) || die "Could not open $file: $!\n";
binmode(FH);
# Read index record header, pg 371
seek(FH,0,0);
read(FH,$data,24);
parseRecHdr($data);
# Read index node header, pg 373
seek(FH,24,0);
read(FH,$data,16);

my %node = parseNodeHdr($data);
printf "Offset to start of index entry list: 0x%x\n",$node{start_ofs};
printf "Offset to end of last list entry   : 0x%x\n",$node{end_ofs};
printf "Offset to end of alloc list buffer : 0x%x\n",$node{alloc_ofs};
printf "Flags                              : 0x%x\n",$node{flags};

print "\n";
my $ofs = 24 + $node{start_ofs};
while ($ofs <= $node{end_ofs}) {
# read first entry
	seek(FH, $ofs,0);
	read(FH,$data,16);
	my %fn = parseFNAttr1($data);
#	print  "Length of entry     : ".$fn{len}." bytes\n";
#	print  "Lenght of \$FN attr  : ".$fn{len_fn}." bytes\n";
#	printf "Flags               : 0x%x\n",$fn{flags};
#	print "\n";
	seek(FH, $ofs,0);
	read(FH,$data,$fn{len});
	my %fn = parseFNAttr2($data);
	print $fn{name}."\n";
	print "M = ".gmtime($fn{m_time})." Z\n";
	print "A = ".gmtime($fn{a_time})." Z\n";
	print "C = ".gmtime($fn{mft_m_time})." Z\n";
	print "B = ".gmtime($fn{c_time})." Z\n";
	print "\n";
	$ofs += $fn{len};
}

close(FH);

sub parseRecHdr {
	my $data = shift;
	my %hdr;
	$hdr{index} = substr($data,0,4);
	$hdr{ofs_fixup} = unpack("v",substr($data,4,2));
	$hdr{num_fixup} = unpack("v",substr($data,6,2));
	printf "Offset to fixup array: 0x%x\n",$hdr{ofs_fixup};
	print  "Number of entries    : ".$hdr{num_fixup}."\n";
#	print $hdr{index}."\n";
}

sub parseNodeHdr {
	my $data = shift;
	my %node;
	($node{start_ofs},$node{end_ofs},$node{alloc_ofs},$node{flags}) = unpack("V4",$data);
	return %node;
}

sub parseFNAttr1 {
	my $data = shift;
	my %fn;
	($fn{len},$fn{len_fn},$fn{flags}) = unpack("x8vvV",$data);
	return %fn;
}

sub parseFNAttr2 {
	my $data = shift;
	my %fn;
	($fn{len},$fn{len_fn},$fn{flags}) = unpack("x8vvV",substr($data,0,16));
	
	my $content = substr($data,16,$fn{len_fn});
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
	$fn{len_name} = $fn{len_name} * 2 if ($fn{namespace} > 0);
	$fn{name} = substr($content,66,$fn{len_name});
#	$fn{name} = decode("ucs-2le",$fn{name}) if ($fn{namespace} > 0);
	$fn{name} = cleanStr($fn{name}) if ($fn{namespace} > 0);
	return %fn;
}



sub parseDirIndxEntry {
	my $data = shift;
	
	
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
	my $st = join('',@t);
	$st =~ s/\x07/\x2E/;
	return $st;
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