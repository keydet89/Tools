#! c:\perl\bin\perl.exe
#------------------------------------------------------
# jobparse.pl
# Perl script to parse .job file metadata
#
# usage: jobparse.pl [options] (see _syntax())
# 
# References:
#   http://msdn.microsoft.com/en-us/library/cc248285%28PROT.13%29.aspx
#
# Change History:
#   20120416 - updated to address tasks that have not run
#   20090917 - created
#              
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey keydet89@yahoo.com
#------------------------------------------------------
use strict;
use Time::Local;
use Getopt::Long;
my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(dir|d=s file|f=s server|s=s tln|t csv|c help|?|h));

if ($config{help} || ! %config) {
	_syntax();
	exit 1;
}

my $data;
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
	@list = grep{/\.job$/} readdir(DIR);
	closedir(DIR);
	map {$files[$_] = $config{dir}.$list[$_]}(0..scalar(@list) - 1);
}
else {
	die "You have selected neither a directory nor a file.\n";
}

foreach my $file (@files) {
	open(FH,"<",$file) || die "Could not open $file: $!\n";
	binmode(FH);
	seek(FH,0,0);
# Read the header information
	read(FH,$data,0x44);
	my %hdr = parseJobHeader($data);

# Running instance Count
	seek(FH,0x44,0);
	read(FH,$data,2);
	$hdr{running_instance_count} = unpack("v",$data);

# Read the appname
	my $tag = 1;
	my $ofs = 0;
	while($tag) {
		seek(FH,$hdr{app_name_offset} + $ofs,0);
		read(FH,$data,2);
		if (unpack("v",$data) == 0x00) {
			$ofs += 2;
			$tag = 0;
		}
		else {
			$hdr{app_name} .= $data;
			$ofs += 2;
		}
	}
	$hdr{app_name} =~ s/\00//g;
#printf "Offset = 0x%x\n",$hdr{app_name_offset} + $ofs;
# Get Parameters
	my $start = $hdr{app_name_offset} + $ofs;
	my $tag = 1;
	my $ofs = 0;
	while ($tag) {
		seek(FH,$start + $ofs,0);
		read(FH,$data,2);
		if (unpack("v",$data) == 0x00) {
			$tag = 0;
		}
		else {
			$hdr{parameters} .= $data;
			$ofs += 2;
		}
	}
	$hdr{parameters} =~ s/\00//g;
	$hdr{parameters} =~ s/[[:cntrl:]]//g;

	close(FH);

#-----------------------------------------------------------
	my %status = (0x00041300 => "Task is ready to run",
  	            0x00041301 => "Task is running",
    	          0x00041302 => "Task is disabled",
      	        0x00041303 => "Task has not run",
        	      0x00041304 => "No more scheduled runs",
          	    0x00041305 => "Properties not set",
            	  0x00041306 => "Last run terminated by user",
              	0x00041307 => "No triggers/triggers disabled",
              	0x00041308 => "Triggers do not have set run times");

	if ($config{csv}) {
		my $status;
		if (exists $status{$hdr{status}}) {
			$status = $status{$hdr{status}};
		}
		else {
			$status = sprintf "0x%08x",$hdr{status};
		}
		print $hdr{last_run_date}.",".$hdr{app_name}." ".$hdr{parameters}.",".$status."\n";
	}
	elsif ($config{tln}) {
		my $descr = $hdr{app_name}." ".$hdr{parameters};
		$descr .= "  Status: ".$status{$hdr{status}} if (exists $status{$hdr{status}});
		my $str = $hdr{last_run_date_as_epoch}."|JOB|".$config{server}."||".$descr;
		print $str."\n";
	}
	else {
#		$hdr{app_name} =~ s/\W//g;
		print "Command      : ".$hdr{app_name}." ".$hdr{parameters}."\n";
		print "Status       : ".$status{$hdr{status}}."\n" if (exists $status{$hdr{status}});
		
		my $last_run;
		if ($hdr{last_run_date_as_epoch} == 0) {
			$last_run = "Never";
		}
		else {
			$last_run = $hdr{last_run_date};
		}
		
		print "Last Run Date: ".$last_run."\n";
		printf "Exit Code    : 0x%x\n",$hdr{exit_code};
		print "\n";
	}
}
	
#---------------------------------------------------------
# _syntax()
# 
#---------------------------------------------------------
sub _syntax {
print<< "EOT";
jobparse [option]
Parse XP/2003 \.job file metadata

  -d directory...parse all files in directory
  -f file........parse a single \.job file
  -c ............Comma-separated (.csv) output (open in Excel)
  -t ............get \.job metadata in TLN format   
  -s server......add name of server to TLN ouput (use with -t)           
  -h ............Help (print this information)
  
Ex: C:\\>jobparse -f <path_to_job_file> -t
    C:\\>jobparse -d C:\\Windows\\Tasks -c

**All times printed as GMT/UTC

copyright 2012 Quantum Analytics Research, LLC
EOT
}

#---------------------------------------------------------
# parseJobHeader()
# 
#---------------------------------------------------------
sub parseJobHeader {
	my $data = shift;
	my %hdr;
#	my @vals = unpack("v16V5v8",$data);
	my @vals = unpack("v16V5",$data);
	
	$hdr{prod_ver} = $vals[0];
	$hdr{file_ver} = $vals[1];
# MS def of UUID: http://msdn.microsoft.com/en-us/library/cc232144%28PROT.13%29.aspx#universal_unique_identifier
	$hdr{app_name_offset} = $vals[10];
	$hdr{err_retry_int} = $vals[13];
	$hdr{exit_code} = $vals[18];
# Status codes: http://msdn.microsoft.com/en-us/library/aa383604%28VS.85%29.aspx
	$hdr{status} = $vals[19];
	
	
	my $datebytes = substr($data,0x34,16);
	$hdr{last_run_date} = parseDate128($datebytes);
	$hdr{last_run_date_as_epoch} = parseDate128AsEpoch($datebytes);
	
	return %hdr;
}

#---------------------------------------------------------
# parseDate128()
# 
#---------------------------------------------------------
sub parseDate128 {
	my $date = $_[0];
	my @months = ("Jan","Feb","Mar","Apr","May","Jun","Jul",
	              "Aug","Sep","Oct","Nov","Dec");
	my @days = ("Sun","Mon","Tue","Wed","Thu","Fri","Sat");
	my ($yr,$mon,$dow,$dom,$hr,$min,$sec,$ms) = unpack("v8",$date);
	if ($yr == 0) {
		return 0;
	}
	else {
		$hr = "0".$hr if ($hr < 10);
		$min = "0".$min if ($min < 10);
		$sec = "0".$sec if ($sec < 10);
		my $str = $days[$dow]." ".$months[$mon - 1]." ".$dom." ".$hr.":".$min.":".$sec." ".$yr;
		return $str;
	}
}

#---------------------------------------------------------
# parseDate128AsEpoch()
# 
#---------------------------------------------------------
sub parseDate128AsEpoch {
	my $date = $_[0];
#	my @months = ("Jan","Feb","Mar","Apr","May","Jun","Jul",
#	              "Aug","Sep","Oct","Nov","Dec");
#	my @days = ("Sun","Mon","Tue","Wed","Thu","Fri","Sat");
	my ($yr,$mon,$dow,$dom,$hr,$min,$sec,$ms) = unpack("v8",$date);
	
	if ($yr == 0) {
		return 0;
		
	}
	else {
# $time = timegm($sec,$min,$hour,$mday,$mon,$year);
		my $epoch = timegm($sec,$min,$hr,$dom,$mon,$yr);
		return $epoch;
	}
}