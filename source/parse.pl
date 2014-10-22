#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# parse.pl - parse an event file containing events in TLN (ie,
#  5-field) format; output goes to STDOUT, can redirect to a 
#  file.
# 
# Change History: 
#   20130417 - added option to list events oldest first;
#   20110523 - modified time module to Time::Local
#   20110511 - added csv output option
#   20090610 - added command line options, date range parsing
#
# copyright 2013 Quantum Analytics Research, LLC 
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
use strict;
use Getopt::Long;
use Time::Local;

my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(file|f=s range|r=s csv|c old|o zone|z=i help|?|h));

if ($config{help} || ! %config) {
	_syntax();
	exit 1;
}

# Get the filename
die "You must include a filename.\n" unless ($config{file});
die "File not found.\n" unless (-e $config{file});

# Hash to hold values
my %tl;

# Range values (if used)
my ($epoch1,$epoch2);

# Check for ranges
if ($config{range}) {
	my ($dt1,$dt2) = split(/-/,$config{range});
	my ($m1,$d1,$y1) = split(/\//,$dt1);
	my $first = $y1.$m1.$d1;

	die "Invalid date.  Input DD/MM/YYYY.\n" if (($d1 < 1 || $d1 > 31) || ($m1 < 1 || $m1 > 12));

	my ($m2,$d2,$y2) = split(/\//,$dt2);
	my $last = $y2.$m2.$d2;

	if ($first <= $last) {
		$epoch1 = getEpoch($y1,$m1,$d1,0,0,0);
		$epoch2 = getEpoch($y2,$m2,$d2,23,59,59);
#		print gmtime($epoch1)."\n";
#		print gmtime($epoch2)."\n";
	}
	else {
# Second date in the range is smaller than the first, so we just 
# reverse them
		$epoch1 = getEpoch($y2,$m2,$d2,23,59,59);
		$epoch2 = getEpoch($y1,$m1,$d1,0,0,0);
	}
}

open(FH,"<",$config{file}) || die "Could not open $config{file}:$!\n";
while(<FH>) {
	chomp;
	my ($t, $rest) = (split(/\|/,$_,2))[0,1];
	if ($config{range}) {
		push(@{$tl{$t}},$rest) if ($t > $epoch1 && $t < $epoch2);
	}
	else {
		push(@{$tl{$t}},$rest);
	}
}
close(FH);

if ($config{csv}) {
 if ($config{old}) {
		foreach my $i (sort {$a <=> $b} keys %tl) {
			my $csvtime = getDateFromEpoch($i);
#		my $csvtime = gmtime($i);
			my @events = uniq(@{$tl{$i}});
			foreach my $n (@events) {
				my ($type,$sys,$user,$desc) = split(/\|/,$n,4);
				eval {
					print $csvtime.",".$type.",".$sys.",".$user.",".$desc."\n";
				};
			}
		}
	}
	else {
		foreach my $i (reverse sort {$a <=> $b} keys %tl) {
			my $csvtime = getDateFromEpoch($i);
#		my $csvtime = gmtime($i);
			my @events = uniq(@{$tl{$i}});
			foreach my $n (@events) {
				my ($type,$sys,$user,$desc) = split(/\|/,$n,4);
				eval {
					print $csvtime.",".$type.",".$sys.",".$user.",".$desc."\n";
				};
			}
		}
	}
}
else {
	if ($config{old}) {
		foreach my $i (sort {$a <=> $b} keys %tl) {
			print gmtime($i)." Z\n";
			my @events = uniq(@{$tl{$i}});
			foreach my $n (@events) {
				my ($type,$sys,$user,$desc) = split(/\|/,$n,4);
				eval {
					printf "  %-8s %-16s $user - $desc\n",$type,$sys;
				};
			}
			print "\n";
		}
	}
	else {
		foreach my $i (reverse sort {$a <=> $b} keys %tl) {
			print gmtime($i)." Z\n";
			my @events = uniq(@{$tl{$i}});
			foreach my $n (@events) {
				my ($type,$sys,$user,$desc) = split(/\|/,$n,4);
				eval {
					printf "  %-8s %-16s $user - $desc\n",$type,$sys;
				};
			}
			print "\n";
		}
	}
}

sub getEpoch {
	my ($yy,$mm,$dd,$hr,$min,$sec) = @_;
	
	my $epoch = timegm($sec,$min,$hr,$dd,$mm - 1,$yy);
	return $epoch;
}

# ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime(time)
sub getDateFromEpoch {
	my $epoch = shift;
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime($epoch);
	$mon++;
	$mon = "0".$mon if ($mon < 10);
	$hour = "0".$hour if ($hour < 10);
	$min = "0".$min if ($min < 10);
	$sec = "0".$sec if ($sec < 10);
	my $str = ($year + 1900)."-".$mon."-".$mday." ".$hour.":".$min.":".$sec;
	return $str;
}

# remove duplicate lines from an array, return an array
sub uniq {
    return keys %{{ map { $_ => 1 } @_ }};
}

sub _syntax {
print<< "EOT";
parse [option]
Parse contents event file to produce a timeline; output goes to STDOUT

  -f file........event file to be parsed; must be 5-field TLN
                 format
  -c ............CSV output format (for opening in Excel), time in 
                 YYYYMMDDhhmmss format
  -o ............sort showing oldest events first               
  -r range ......range of dates, MM/DD/YYYY-MM/DD/YYYY format; time range of
                 00:00:00 is automatically added to the first date, and 
                 23:59:59 is automatically added to the second date.                         
  -h ............Help (print this information)
  
Ex: C:\\>parse -f events\.txt -o > tln\.txt
    C:\\>parse -f events\.txt -r 02/12/2008-03/16/2008 > tln\.txt
    C:\\>parse -f events\.txt -c > tln\.csv

**All times printed as GMT/UTC

copyright 2013 Quantum Analytics Research, LLC
EOT
}