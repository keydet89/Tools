#! c:\perl\bin\perl.exe
#------------------------------------------------------
# pref.pl
# Perl script to parse the contents of Windows application prefetch files
#
# usage: pref.pl [optoins] (see _syntax()]
# 
# Ref: http://www.42llc.net/index.php?option=com_myblog&Itemid=39
#
# Change History:
#   20130603 - removed 'outlier' code, updated minimum output, added alert 
#              functionality
#   20120620 - updated to include path to EXE, if avail., in TLN output
#   20120608 - added category tag to TLN output
#   20120308 - added outliers capability
#   20091020 - removed full path for .pf file...was told that it could be 
#              too confusing
#   20090517 - updated output format for volume serial number
#              added TLN output
#		20090516 - added significant code
#
# For TLN output (via '-t'), the script will start with the name of the Prefetch
# file (ie, EXE-hash.pf), and attempt to get the name of the EXE, which is often
# embedded in the file itself.  If it does, it will then attempt to locate the 
# path to the EXE within the list of modules.  If it does find the path, it will
# use that in the TLN output; otherwise, it will use the EXE name, or the file name.
# This applies to all but the RunDLL32.exe entries; in those cases, just the Prefetch
# filename is used.
#
# copyright 2013 Quantum Analytics Research, LLC
# Author H. Carvey keydet89@yahoo.com
#------------------------------------------------------
use strict;
use Pref;
use Getopt::Long;
my %config = ();
my @alerts = ("recycle","globalroot","temp","system volume information","appdata",
	            "application data");

my @printAlerts = ();
my $lce = "";
my ($ver,$p);

Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(dir|d=s file|f=s exe|e alert|a path|p server|s=s info|i tln|t csv|c help|?|h));

if ($config{help} || ! %config) {
	_syntax();
	exit 1;
}

my $server;
($config{server}) ? ($server = $config{server}) : ($server = "");

my @files;

if ($config{file}) {
	die $config{file}." not found.\n" unless (-e $config{file});
	die $config{file}." is not a file.\n" unless (-f $config{file});
	@files = $config{file};
}
elsif ($config{dir}) {
	my @list;
#	die $config{dir}." not found.\n" unless (-e $config{dir});
#	die $config{dir}." is not a directory.\n" unless (-d $config{dir});
	$config{dir} = $config{dir}."\\" unless ($config{dir} =~ m/\\$/);
#	print "DIR = ".$config{dir}."\n";
	opendir(DIR,$config{dir}) || die "Could not open ".$config{dir}.": $!\n";
	@list = grep{/\.pf$/} readdir(DIR);
	closedir(DIR);
	map {$files[$_] = $config{dir}.$list[$_]}(0..scalar(@list) - 1);
}
else {
	die "You have selected neither a directory nor a file.\n";
}

# This section gets all of the basic data for each file
my %pref = ();
foreach my $file (@files) {
	my @n = split(/\\/,$file);
	my $last = scalar(@n) - 1;
	my $name = $n[$last];
	
	$p = pref->new($file);
	next if ($p->getSig() ne "SCCA");
	$ver = $p->getVersion();
	my $e = $p->getExeName();
	($pref{$file}{runcount},$pref{$file}{lastrun}) = $p->getMetaData();
	
	my @paths = $p->getPaths();
	foreach my $path (@paths) {
		my $lcpath = $path;
		$lcpath =~ tr/[A-Z]/[a-z]/;
		$lce = $e;
		$lce =~ tr/[A-Z]/[a-z]/;
# This is kind of crude hack; I had a path that had a '(' in it
# so I trimmed the string		
		$lce = substr($lce,0,24) if (length($lce) > 24);		
		$pref{$file}{exepath} = $path if ($lcpath =~ m/$lce$/);	
	}
	$pref{$file}{exepath} = $e if ($pref{$file}{exepath} eq "");
	$pref{$file}{paths} = join('|',@paths);
	
	my %vib = $p->getVibData();
	$pref{$file}{volumepath} = $vib{volumepath};
	$pref{$file}{volcreation} = $vib{creationdate};
	$pref{$file}{vsn} = $vib{volumeserial};
}

# Output formats	
if ($config{csv}) {
	print "File,EXE Path,Last Run Time,Run Count\n";
	foreach my $f (keys %pref) {
		print $f.",".$pref{$f}{exepath}.",".gmtime($pref{$f}{lastrun}).",".$pref{$f}{runcount}."\n";
	}
}
elsif ($config{tln}) {
	foreach my $f (keys %pref) {
		if ($ver == 0x1A) {
# Win8
			my @rts = $p->getRuntimes();
			foreach my $i (0..(scalar(@rts) - 1)) {
				if ($i == 0) {
					print $rts[$i]."|PREF|".$config{server}."||[ProgExec] ".$pref{$f}{exepath}." last run [run count: ".$pref{$f}{runcount}."]\n";
				}
				else {
					print $rts[$i]."|PREF|".$config{server}."||[ProgExec] ".$pref{$f}{exepath}." previous run \n";
				}
			}				
		}
		else {
			print $pref{$f}{lastrun}."|PREF|".$config{server}."||[ProgExec] ".$pref{$f}{exepath}." last run [".$pref{$f}{runcount}."]\n";
		}
# Generate alerts (TLN)		
		my $lcf = $f;
		$lcf =~ tr/[A-Z/[a-z]/;
		foreach my $a (@alerts) {
			next if (grep(/iexplore\.exe/,$lce) && $a eq "temp");
			push(@printAlerts,$pref{$f}{lastrun}."|ALERT|".$config{server}."||".$f.": ".$pref{$f}{exepath}." path contains ".$a) if (grep(/$a/,$lcf));
		}
		
		my @list = split(/\|/,$pref{$f}{paths});
		foreach my $l (@list) {
			my $lcl = $l;
			$lcl =~ tr/[A-Z]/[a-z]/;
			foreach my $a (@alerts) {
				push(@printAlerts, $pref{$f}{lastrun}."|ALERT|".$config{server}."||".$f.": ".$l." path contains ".$a) if (grep(/$a/,$lcl));
			}
		
			if ($lcl =~ m/\.cpl$/) {
				push(@printAlerts,$pref{$f}{lastrun}."|ALERT|".$config{server}."||".$f.": ".$l." path ends in \.cpl");
			}
		
			if ($lcl =~ m/\.dat$/ || $lcl =~ m/\.bat$/) {
				push(@printAlerts,$pref{$f}{lastrun}."|WARN|".$config{server}."||".$f.": ".$l." path ends in \.dat/\.bat");
			}
		
			my @break = split(/\\/,$l);
			my $last = scalar(@break) - 1;
			push(@printAlerts,$pref{$f}{lastrun}."|ALERT|".$config{server}."||".$f.": ".$l.": Possible ADS") if (grep(/:/,$break[$last]));
		}
	}		
}
else {
	foreach my $f (keys %pref) {
		print "File     : ".$f."\n";
		print "Exe Path : ".$pref{$f}{exepath}."\n";
		print "Last Run : ".gmtime($pref{$f}{lastrun})."\n";
		print "Run Count: ".$pref{$f}{runcount}."\n";

# Generate alerts
# check EXE path against alerts
		my $lcf = $f;
		$lcf =~ tr/[A-Z]/[a-z]/;
		foreach my $a (@alerts) {
			push(@printAlerts,"ALERT: ".$pref{$f}{exepath}." path contains ".$a) if (grep(/$a/,$lcf));
		}
				
		if ($config{info}) {
			print "\n";
			print "EXE Name            : ".$pref{$f}{exepath}."\n";
			print "Volume Path         : ".$pref{$f}{volumepath}."\n";
			print "Volume Creation Date: ".gmtime($pref{$f}{volcreation})." Z\n";
			print "Volume Serial Number: ".$pref{$f}{vsn}."\n";
		}
		
		my @list = split(/\|/,$pref{$f}{paths});
		foreach my $l (@list) {
			my $lcl = $l;
			$lcl =~ tr/[A-Z]/[a-z]/;
			foreach my $a (@alerts) {
				next if (grep(/iexplore\.exe/,$lce) && $a eq "temp");
				push(@printAlerts,"ALERT: ".$pref{$f}{exepath}." module ".$l." path contains ".$a) if (grep(/$a/,$lcl));
			}
			
			if ($lcl =~ m/\.dat$/ || $lcl =~ m/\.bat$/) {
				next if (grep(/iexplore\.exe/,$lce) && $lcl =~ m/\.dat$/); 
				push(@printAlerts,"ALERT: ".$pref{$f}{exepath}." module ".$l." path ends in \.dat/\.bat");
			}
		
			my @break = split(/\\/,$l);
			my $last = scalar(@break) - 1;
			push(@printAlerts,"ALERT: ".$pref{$f}{exepath}." module ".$l." path: Possible ADS") if (grep(/:/,$break[$last]));
		
		}
	
		if ($config{path}) {
			print "\n";
			print "Module paths: \n";
			my @list = split(/\|/,$pref{$f}{paths});
			foreach my $l (@list) {
				print "  ".$l."\n";
			}
		}
		print "\n";
	}	

}


if ($config{alert} && scalar(@printAlerts) > 0) {
	foreach (@printAlerts) {
		print $_."\n";
	}			
}

	
sub _syntax {
print<< "EOT";
pref [option]
Parse metadata from Windows app prefetch files

  -d directory...parse all \.pf files in directory
  -f file........parse a single \.pf file
  -a ............Generate alerts
  -p ............list filepath strings (only with -f)
  -i ............list volume information block data
  -e ............Print only exe paths (use only with -d)
  -c ............Comma-separated (.csv) output (open in Excel)
                 Gets ONLY MAC times and runcount/last runtime
  -t ............get \.pf metadata in TLN format   
  -s server......add name of server to TLN ouput (use with -t)           
  -h ............Help (print this information)
  
Ex: C:\\>pref -f <path_to_Pretch_file>
    C:\\>pref -d C:\\Windows\\Prefetch -c

**All times printed as GMT/UTC

copyright 2013 Quantum Analytics Research, LLC
EOT
}