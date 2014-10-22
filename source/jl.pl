#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# This is a simple script to demonstrate the use of the JumpList.pm
# module; outputs in .csv and TLN output
#
# Author: H. Carvey, keydet89@yahoo.com
# copyright 2011-2012 Quantum Research Analytics, LLC
#-----------------------------------------------------------
use strict;
use JumpList;
use Getopt::Long;
my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(dir|d=s file|f=s server|s=s user|u=s tln|t csv|c help|?|h));

if ($config{help} || ! %config) {
	_syntax();
	exit 1;
}

my $server;
($config{server}) ? ($server = $config{server}) : ($server = "");

my @files;

if ($config{dir}) {
	$config{dir} .= "\\" unless ($config{dir} =~ m/\\$/);
	opendir(DIR,$config{dir});
	while (my $f = readdir(DIR)) {
		next unless ($f =~ m/\.automaticDestinations-ms$/);
		push(@files,$config{dir}.$f);
	}
	close(DIR);
}

push(@files,$config{file}) if ($config{file});

my %hash;
foreach (@files) {
	%hash = ();
	print "\n" unless ($config{tln});
	print $_."\n" unless ($config{tln});
	my $jl = JumpList->new($_);
	my %dl = ();
	%dl = $jl->getDestList();
	
	foreach my $k (keys %dl) {
		my $t = $dl{$k}{position};
		my $mru = $dl{$k}{mrutime};
#		my $str = $jl->getStream($k);
#		next if (length($str) < 0x4C);
		push(@{$hash{$mru}},$dl{$k}{str});
	}
	
	if ($config{csv}) {
		foreach my $t (reverse sort {$a <=> $b} keys %hash) {
			foreach my $i (@{$hash{$t}}) {
				print gmtime($t).",".$i."\n";
			}
		}
	}
	elsif ($config{tln}) {
		foreach my $t (reverse sort {$a <=> $b} keys %hash) {
			foreach my $i (@{$hash{$t}}) {
				print $t."|JumpList|".$config{server}."|".$config{user}."|".$i."\n";
			}
		}
	}
	else {
		foreach my $t (reverse sort {$a <=> $b} keys %hash) {
			print gmtime($t)."\n";
			foreach my $i (@{$hash{$t}}) {
				print "  ".$i."\n";
			}
		}
		print "\n";
	}  
}

sub _syntax {
print<< "EOT";
jl [option]
Parse DestList stream from Win7 *\.autoDest Jump List files

  -d directory...parse all Jump List files in directory
  -f file........parse a single Jump List file
  -c ............Comma-separated (.csv) output (open in Excel)
  -t ............output in TLN format   
  -s server......add name of server to TLN ouput (use with -t)  
  -u user........add username to TLN output (use with -t)         
  -h ............Help (print this information)
  
Ex: C:\\>jl -f <path_to_Jump_List_file> -t
    C:\\>jl -d C:\\Users\\..\\AutomaticDestinations -c

**All times printed as GMT/UTC

copyright 2012 Quantum Analytics Research, LLC
EOT
}   