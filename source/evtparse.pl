#! c:\perl\bin\perl.exe
#---------------------------------------------------------------------
# evtparse.pl - script to parse Windows 2000/XP/2003 Event Log files
#   Output is in TLN format, goes to STDOUT
# 
# Change History
#    20100607 - added .csv output
#    20091020 - added -d switch to get all .evt files in a directory
#    20091018 - added Getopt::Long and ability to dump record numbers and
#               time generated values (ie, check for alterations in system
#               time)
#
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#---------------------------------------------------------------------
use strict;
use Getopt::Long;

my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(dir|d=s evt|e=s tln|t seq|s help|?|h));

if ($config{help} || ! %config) {
	_syntax();
	exit 1;
}
my %seq;

my @files;
if ($config{evt}) {
	die $config{evt}." not found.\n" unless (-e $config{evt});
	die $config{evt}." is not a file.\n" unless (-f $config{evt});
	push(@files,$config{evt});
}
elsif ($config{dir}) {
	my @list;
#	die $config{dir}." not found.\n" unless (-e $config{dir});
#	die $config{dir}." is not a directory.\n" unless (-d $config{dir});
	$config{dir} = $config{dir}."\\" unless ($config{dir} =~ m/\\$/);
#	print "DIR = ".$config{dir}."\n";
	opendir(DIR,$config{dir}) || die "Could not open ".$config{dir}.": $!\n";
	@list = grep{/\.evt$/i} readdir(DIR);
	closedir(DIR);
	map {$files[$_] = $config{dir}.$list[$_]}(0..scalar(@list) - 1);
}
else {
	die "You have selected neither a directory nor a file.\n";
}

foreach my $file (@files) {
	my $data;
	my $size = (stat($file))[7];
	my $ofs = 0;
	open(FH,"<",$file) || die "Could not open $file: $!\n";
	binmode(FH);

	my %types = (0x0001 => "Error",
             	0x0010 => "Failure",
             	0x0008 => "Success",
             	0x0004 => "Info",
             	0x0002 => "Warn");

	while ($ofs < $size) {
		seek(FH,$ofs,0);
		read(FH,$data,4);
		if (unpack("V",$data) == 0x654c664c) {
#			printf "Magic number located at offset 0x%x\n",$ofs;
			seek(FH,$ofs - 4,0);
			read(FH,$data,4);
			my $l = unpack("V",$data);
			seek(FH,$ofs - 4,0);
			read(FH,$data,$l);
			my $f = unpack("V",substr($data,$l - 4,4));
#		printf "Record located at offset 0x%08x; Length = 0x%x, Final Length = 0x%x\n",$ofs - 4,$l,$f;
			if ($l == $f) {
#			print "\t-> Valid record\n";
#			print "\t**HDR Record\n" if ($l == 0x30);
#			print "\t**EOF Record\n" if ($l == 0x28);		
				if ($l > 0x38) {
					my %r = parseRec($data);
					my $r_ofs = sprintf "0x%08x",$ofs;
#				print $r_ofs."|".$r{rec_num}."|".$r{evt_id}."|".$r{source}."|".$r{computername}."|".$r{sid}."|".$r{strings}."\n";				
					if ($config{seq}) {
						my $str = gmtime($r{time_gen});
						printf "%-8s %-24s\n",$r{rec_num},$str;
					}
					elsif ($config{tln}) {
						my $desc = $r{source}."/".$r{evt_id}.";".$types{$r{evt_type}}.";".$r{strings};
						print $r{time_gen}."|EVT|".$r{computername}."|".$r{sid}."|".$desc."\n";
					}
					else {
						$r{strings} =~ s/,/;/g;
						print gmtime($r{time_gen})." Z,".$r{computername}.",".$r{sid}.",".$r{source}.",".
						      $r{evt_id}.",".$types{$r{evt_type}}.",".$r{strings}."\n";
					}
				}
				$ofs += $l;
			}
			else {
# If this check ($l == $f) fails, then the record isn't valid
				$ofs += 4;
			}
		}
		else {
			$ofs += 4;
		}
	}
	close(FH);
}

#---------------------------------------------------------------------
# parseRec()
# Parse the binary Event Record
# References:
#   http://msdn.microsoft.com/en-us/library/aa363646(VS.85).aspx  
#---------------------------------------------------------------------
sub parseRec {
	my $data = shift;
	my %rec;
	my $hdr = substr($data,0,56);
	($rec{length},$rec{magic},$rec{rec_num},$rec{time_gen},$rec{time_wrt},
	$rec{evt_id},$rec{evt_id2},$rec{evt_type},$rec{num_str},$rec{category},
	$rec{c_rec},$rec{str_ofs},$rec{sid_len},$rec{sid_ofs},$rec{data_len},
	$rec{data_ofs}) = unpack("V5v5x2V6",$hdr); 
	
# Get the end of the Source/Computername field
	my $src_end;
	($rec{sid_len} == 0) ? ($src_end = $rec{str_ofs}) : ($src_end = $rec{sid_ofs});
	my $s = substr($data,0x38,$src_end);
	($rec{source},$rec{computername}) = (split(/\x00\x00/,$s))[0,1];
	$rec{source} =~ s/\x00//g;
	$rec{computername} =~ s/\x00//g;
	
# Get SID
	if ($rec{sid_len} > 0) {
		my $sid = substr($data,$rec{sid_ofs},$rec{sid_len});
		$rec{sid} = translateSID($sid);
	}
	else {
		$rec{sid} = "N/A";
	}
	
# Get strings from event record
	my $strs = substr($data,$rec{str_ofs},$rec{data_ofs} - $rec{str_ofs});
	my @str = split(/\x00\x00/,$strs, $rec{num_str});
	$rec{strings} = join(',',@str);
	$rec{strings} =~ s/\x00//g;
	$rec{strings} =~ s/\x09//g;
	$rec{strings} =~ s/\n/ /g;
	$rec{strings} =~ s/\x0D//g;

	return %rec;
}

#---------------------------------------------------------------------
# translateSID()
# Translate binary data into a SID
# References:
#   http://blogs.msdn.com/oldnewthing/archive/2004/03/15/89753.aspx  
#   http://support.microsoft.com/kb/286182/
#   http://support.microsoft.com/kb/243330
#---------------------------------------------------------------------
sub translateSID {
	my $sid = $_[0];
	my $len = length($sid);
	my $revision;
	my $dashes;
	my $idauth;
	if ($len < 12) {
# Is a SID ever less than 12 bytes?		
		return "SID less than 12 bytes";
	}
	elsif ($len == 12) {
		$revision = unpack("C",substr($sid,0,1));
		$dashes   = unpack("C",substr($sid,1,1));
		$idauth   = unpack("H*",substr($sid,2,6));
		$idauth   =~ s/^0+//g;
		my $sub   = unpack("V",substr($sid,8,4));
		return "S-".$revision."-".$idauth."-".$sub;
	}
	elsif ($len > 12) {
		$revision = unpack("C",substr($sid,0,1));
		$dashes   = unpack("C",substr($sid,1,1));
		$idauth   = unpack("H*",substr($sid,2,6));
		$idauth   =~ s/^0+//g;
		my @sub   = unpack("V*",substr($sid,8,($len-2)));
		my $rid   = unpack("v",substr($sid,24,2));
		my $s = join('-',@sub);
		return "S-".$revision."-".$idauth."-".$s;
#		return "S-".$revision."-".$idauth."-".$s."-".$rid;
	}
	else {
# Nothing to do		
	}
}

sub _syntax {
print<< "EOT";
evtparse [option]
Parse Event log (Win2000, XP, 2003)

  -e file........Event log (full path)
  -d dir.........Directory where .evt files are located
  -s ............Output in sequential format (record number and time 
                 generated values ONLY - use to see if system time may
                 have been tampered with)
  -t ............TLN output (default .csv)                      
  -h ............Help (print this information)
  
Ex: C:\\>evtparse -e secevent.evt -t > timeline.txt
    C:\\>evtparse -e sysevent.evt -s

**All times printed as GMT/UTC

copyright 2012 Quantum Analytics Research, LLC
EOT
}