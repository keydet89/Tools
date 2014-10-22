#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# Firefox 3 places.sqlite parsing
#
#
# References:
#  http://kb.mozillazine.org/Places.sqlite
#  https://developer.mozilla.org/en-US/docs/The_Places_database
#  http://www.forensicswiki.org/wiki/Mozilla_Firefox_3_History_File_Format
#
# copyright 2013 Quantum Analytics Research, LLC
# 
#-----------------------------------------------------------
use strict;
use DBI;

my $file = shift || die "You must enter a filename.\n";

my $ver = getVersion($file);
print $ver."\n";

my $db = DBI->connect("dbi:SQLite:dbname=$file","","") || die "Unable to connect to $file: $!\n";
$db->prepare("SELECT id FROM moz_places LIMIT 1") || die "The database is not a correct Firefox database\n";;
# Get bookmarks
#my $bm = $db->prepare("SELECT moz_bookmarks.dateAdded/1000000,moz_bookmarks.lastModified/1000000,
#          moz_places.url, moz_places.visit_count FROM 
#          moz_bookmarks, moz_places WHERE moz_places.id = moz_bookmarks.fk ORDER BY 
#          moz_bookmarks.dateAdded ASC");
#$bm->execute();

# get history
my $h = $db->prepare("SELECT moz_historyvisits.visit_date/1000000,moz_historyvisits.visit_type,moz_places.url,
         moz_places.rev_host,moz_places.visit_count,moz_places.hidden,moz_places.typed,moz_historyvisits.from_visit
         FROM moz_places,moz_historyvisits
         WHERE moz_places.id = moz_historyvisits.place_id");
$h->execute;
my %res = processResults($h);
$h->finish;
$db->disconnect;

print "Num entries: ".scalar(keys %res)."\n";

foreach my $i (0..(scalar(keys %res) - 1)) {
	print $res{$i}{visit_date}."  ".$res{$i}{url}."  ".$res{$i}{from_visit}."\n";
	
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
		$hash{$count}{visit_date} = $row[0];
		$hash{$count}{visit_type} = $row[1];
		$hash{$count}{url} = $row[2];
		$hash{$count}{host} = reverse($row[3]);
		$hash{$count}{visit_count} = $row[4];
		$hash{$count}{hidden} = $row[5];
		$hash{$count}{typed} = $row[6];
		$hash{$count}{from_visit} = $row[7];
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