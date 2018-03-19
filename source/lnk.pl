#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# This is a simple script to demonstrate the use of the LNK.pm module.
#
# History:
#   20180319 - updated to include displaying icon filename path
#
# copyright 2011-2018 Quantum Research Analytics, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
use strict;
use LNK;

my @files;
my $file = shift || die "You must enter a file name or dir path\.\n";

my %vals = (0 => "mtime",
            1 => "atime",
            2 => "ctime",
            3 => "workingdir",
            4 => "basepath",
            5 => "description",
            6 => "machineID",
            7 => "birth_obj_id_node",
            8 => "shitemidlist",
            9 => "vol_sn",
            10 => "vol_type",
            11 => "commandline",
            12 => "iconfilename");

if (-d $file) {
	$file = $file."\\" unless ($file =~ m/\\$/);
	opendir(DIR,$file) || die "Could not open directory ".$file.": $!\n";
	my @d = readdir(DIR);
	closedir(DIR);
	
	foreach (@d) {
		next if ($_ =~ m/^\./);
#		next unless ($_ =~ m/\.lnk$/);
		push(@files,$file.$_);
	}

}
elsif (-f $file) {
	
	push(@files,$file);
}
else {}

foreach my $f (@files) {
	my $lnk = LNK->new();
	print "File: ".$f."\n";
	my %shrt = $lnk->getLNK($f);
	
	foreach my $i (0..(scalar(keys %vals) - 1)) {
		if (exists $shrt{$vals{$i}}) {
			if ($vals{$i} =~ m/time$/) {
				printf "%-17s  ".gmtime($shrt{$vals{$i}})." UTC\n",$vals{$i};
			}
			else {
				printf "%-17s  %-30s\n",$vals{$i},$shrt{$vals{$i}};
			}
		}
	}
	print "\n";
}

