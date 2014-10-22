#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# tool to parse RecentFileCache.bcf files
#
# copyright 2013 Quantum Analytics Research, LLC
# author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
use strict;

my $file = shift;

my $size = (stat($file))[7];
my $data;
my $offset = 0x14;
my ($sz,$name,$len);

open(FH,"<",$file) || die "Could not open $file: $!\n";
binmode(FH);

while ($offset < $size) {
	seek(FH,$offset,0);
	read(FH,$data,4);
	$sz = unpack("V",$data);
	$offset += 4;
	$len = (($sz + 1) * 2);
	
	seek(FH,$offset,0);
	read(FH,$data,$len);
	$data =~ s/\00//g;
	print $data."\n";
	$offset += $len;

}

close(FH);

