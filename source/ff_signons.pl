#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# Firefox 3 signons.sqlite parsing
#
#
# References:
#  http://kb.mozillazine.org/Places.sqlite
#  https://developer.mozilla.org/en-US/docs/The_Places_database
#  http://www.forensicswiki.org/wiki/Mozilla_Firefox_3_History_File_Format
#
# copyright 2013 Quantum Analytics Research, LLC
# Author: H. Carvey
#-----------------------------------------------------------
use strict;
use DBI;
use Getopt::Long;

my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(file|f=s csv|c tln|t user|u=s server|s=s help|?|h));

if ($config{help} || ! %config) {
	_syntax();
	exit 1;
}
die "You must enter a filename.\n" unless ($config{file});

my $ver = getVersion($config{file});

my $db = DBI->connect("dbi:SQLite:dbname=$config{file}","","") || die "Unable to connect to ".$config{file}.": $!\n";
$db->prepare("SELECT id FROM moz_logins LIMIT 1") || die "The database is not a correct Firefox database\n";;

my $s = $db->prepare("SELECT moz_logins.hostname,moz_logins.timeCreated/1000,moz_logins.timeLastUsed/1000,
             moz_logins.timePasswordChanged/1000,moz_logins.timesUsed
             FROM moz_logins");

$s->execute;
my %res = processResults($s);
$s->finish;
$db->disconnect;


if ($config{csv}) {
	foreach my $i (sort keys %res) {
		print $res{$i}{hostname}.",".$res{$i}{timesUsed}.",".$res{$i}{timeCreated}.",".$res{$i}{timeLastUsed};
		print ",".$res{$i}{timePasswordChanged}."\n";
	}
}
elsif ($config{tln}) {
	foreach my $i (sort keys %res) {
		my $desc = $res{$i}{hostname}." [used ".$res{$i}{timesUsed}." times]";
		print $res{$i}{timeCreated}."|FF_Signon|".$config{server}."|".$config{user}."|pwdCreated|".$desc."\n";
		print $res{$i}{timeLastUsed}."|FF_Signon|".$config{server}."|".$config{user}."|pwdLastUsed|".$desc."\n";
		print $res{$i}{timePasswordChanged}."|FF_Signon|".$config{server}."|".$config{user}."|pwdChanged|".$desc."\n";
	}
}
else {
	print "Database version: ".$ver."\n";
	foreach my $i (sort keys %res) {
		print $res{$i}{hostname}." [".$res{$i}{timesUsed}."]\n";
		print "  Created  : ".gmtime($res{$i}{timeCreated})." UTC\n";
		print "  Last Used: ".gmtime($res{$i}{timeLastUsed})." UTC\n";
		print "  Changed  : ".gmtime($res{$i}{timePasswordChanged})." UTC\n";
		print "\n";
	}
}

#-----------------------------------------------------------
# processResults()
#
# places results in a hash for easy analysis and display
#-----------------------------------------------------------
sub processResults {
	my $res = shift;
	my @row;
	my %hash = ();
	my $count = 0;
	
	while (@row = $res->fetchrow_array()) {
		$hash{$count}{hostname} = $row[0];
		$hash{$count}{timeCreated} = $row[1];
		$hash{$count}{timeLastUsed} = $row[2];
		$hash{$count}{timePasswordChanged} = $row[3];
		$hash{$count}{timesUsed} = $row[4];
		$count++;
	}
	return %hash;
}

sub getVersion {
	my $file = shift;
	my $data;
	open(FH,"<",$file) || die "Could not open $file: $!\n";
	binmode(FH);
	seek(FH,0x60,0);
	read(FH,$data,4);
	close(FH);
	my $ver = unpack("N",$data);
	my @v = split(/0+/,$ver);
	return join('.',@v);
}

sub _syntax {
print<< "EOT";
ff_signons [option]
Parse Firefox signons\.sqlite db

  -f file........Path to a file
  -c ............CSV output 
  -t ............TLN output 
  -s server......Use with -t
  -u user........Use with -t                      
  -h ............Help (print this information)
  
Ex: C:\\>ff_signons -f signons.sqlite
    
**All times printed as GMT/UTC

copyright 2013 Quantum Analytics Research, LLC
EOT
}