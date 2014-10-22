#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# open a file produced by the output of TSK's fls.exe, and 
# translate it into the 5 field timeline format
#
# Change history
#   20100809 - Changed MACE output to MACB, added file size to output 
#
# usage: bodyfile.pl -f [fls_output] -s server > bodyfile.txt
#
# copyright 2012 Quantum Analytics Research, LLC
#----------------------------------------------------------- 
use strict;
use Getopt::Long;

my %config;
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config,qw(server|s=s file|f=s help|?|h));

if ($config{help} || !%config) {
	_syntax();
	exit 1;	
}
die "You must enter a filename.\n" unless ($config{file});

my $server = "" || $config{server};

my %tl;

open(FH,"<",$config{file}) || die "Could not open $config{file}: $!\n";
while(<FH>) {
	chomp;
#	my ($fs,$atime,$mtime,$etime,$ctime) = (split(/\|/,$_,11))[1,7,8,9,10];
	my ($fs,$size,@vals) = (split(/\|/,$_,11))[1,6,7,8,9,10];
	 
	my @dots = qw/. . . ./;
	my %t_hash;

	foreach my $v (@vals) {
		@{$t_hash{$v}} = @dots unless ($v == 0);
	}

	${$t_hash{$vals[0]}}[1] = "A" unless ($vals[0] == 0);
	${$t_hash{$vals[1]}}[0] = "M" unless ($vals[1] == 0);
	${$t_hash{$vals[2]}}[2] = "C" unless ($vals[2] == 0);
	${$t_hash{$vals[3]}}[3] = "B" unless ($vals[3] == 0);

	foreach my $t (reverse sort {$a <=> $b} keys %t_hash) {
		my $str = join('',@{$t_hash{$t}});
		print $t."|FILE|".$server."||".$str." [".$size."] ".$fs."\n";
	}
}
close(FH);

sub _syntax {
print<< "EOT";
Bodyfile [option]
Parse output of TSK fls tool into a 5-field event file; 
  output goes to STDOUT

  -f file........event file to be parsed; must be 5-field TLN
                 format
  -s server......add a server name to the output           
  -h ............Help (print this information)
  
Ex: C:\\>bodyfile.pl -f bodyfile.txt > events.txt
    C:\\>bodyfile.pl -f bodyfile.txt -s SERVER

**All times printed as GMT/UTC

copyright 2012 Quantum Analytics Research, LLC
EOT
}