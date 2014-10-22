#! c:\perl\bin\perl.exe
#---------------------------------------------------------------------
# evtrpt.pl - script to parse Windows 2000/XP/2003 Event Log files
#   and generate a report of the contents (event freq, date range, etc.)
# 
# Change History
#
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#---------------------------------------------------------------------
use strict;

my $file = shift || die "You must enter a filename.\n";
die "File not found.\n" unless (-e $file);
my $data;

# Structures to maintain data
my %freq_types;
my %dates;
my %er;

my %types = (0x0001 => "Error",
             0x0010 => "Failure",
             0x0008 => "Success",
             0x0004 => "Info",
             0x0002 => "Warn");

my $size = (stat($file))[7];
my $ofs = 0;
open(FH,"<",$file) || die "Could not open $file: $!\n";
binmode(FH);

while ($ofs < $size) {
	seek(FH,$ofs,0);
	read(FH,$data,4);
	if (unpack("V",$data) == 0x654c664c) {
		
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
				
				$freq_types{$r{evt_type}}++;
				
				if ($r{source} eq "Security" && ($r{evt_id} > 527 && $r{evt_id} < 541)) {
					my $type = getLoginType($r{evt_id},$r{strings});
					$r{evt_id} = $r{evt_id}.",".$type;
				}
		
				if (exists $er{$r{source}.":".$r{evt_id}}) {
					$er{$r{source}.":".$r{evt_id}}++;
				}
				else {
					$er{$r{source}.":".$r{evt_id}} = 1;
				}
				$dates{$r{time_gen}} = 1;
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

# Print out the report
#print "Total number of event records counted: ".$total."\n";
print "-" x 30,"\n";
print "Event Source/ID Frequency\n";
print "\n";
printf "%-40s %10s %8s\n","Source","Event ID","Count";
printf "%-40s %10s %8s\n","-" x 10,"-" x 8,"-" x 5;
my $er_total = 0;
foreach my $i (sort keys %er) {
	my ($source,$id) = split(/:/,$i,2);
	printf "%-40s %10s %8s\n",$source,$id,$er{$i};
	$er_total += $er{$i};
}
print "\n";
print "Total: ".$er_total."\n";
print "-" x 30,"\n";
print "Event Type Frequency\n";
print "\n";
printf "%-15s  %10s\n","Type","Count";
printf "%-15s  %10s\n","-" x 10,"-" x 5;
my $tot_f = 0;
foreach my $t (keys %freq_types) {
	printf "%-15s  %10s\n",$types{$t},$freq_types{$t};
	$tot_f += $freq_types{$t};
}
# Put this in just as a check to make sure that the total
# adds up correctly
print "\n";
print "Total: ".$tot_f."\n";
print "-" x 30,"\n";
print "Date Range (UTC)\n";
my @daterange = sort {$a <=> $b} keys %dates;
my $i = scalar(@daterange) - 1;
print gmtime($daterange[0])." to ".gmtime($daterange[$i])."\n";

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

#---------------------------------------------------------------------
# getLoginType()
# Returns a login type from the event strings
#---------------------------------------------------------------------
sub getLoginType {
	my $id = shift;
	my $str = shift;
	my @vals = split(/,/,$str);
	if ($id == 528 || $id == 538 || $id == 540) {
		return $vals[4];
	}
	elsif ($id == 529 || $id =~ m/^53/) {
		return $vals[2];
	}
	else {
		return 0;
	}
}