#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# tln.pl
# GUI code to manually generate timeline events, either to display or
# insert into a timeline file
#
#
# Change History:
#  20120516 - updated for compiling
#  20090618 - updated ComboBox code so that user can enter
#             their own source keyword and it will be added to the 
#             events file; also updated the UI so that the date is
#             entered as MM/DD/YYYY
#  20090420 - created
# 
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
#use strict;
use Win32::GUI();
use Time::Local;

#-----------------------------------------------------------
# Global variables
#-----------------------------------------------------------
my $VERSION = "0\.03";

#-----------------------------------------------------------
# GUI
#-----------------------------------------------------------
# create our menu
my $menu = Win32::GUI::MakeMenu(
		"&File"                => "File",
		" > -"                 => 0,
    " > E&xit"             => { -name => "Exit", -onClick => sub {exit 1;}},
    "&Help"                => "Help",
    " > &About"            => { -name => "About", -onClick => \&tln_OnAbout},
);

# Create Main Window
my $main = new Win32::GUI::Window (
    -name     => "Main",
    -title    => "Timeline Entry, v.".$VERSION."  MM/DD/YYYY",
    -pos      => [200, 200],
# Format: [width, height]
    -maxsize  => [580, 290],
    -size     => [580, 290],
    -menu     => $menu,
    -dialogui => 1,
) or die "Could not create a new Window: $!\n";

my $icon_file = "q\.ico";
my $icon = new Win32::GUI::Icon($icon_file);
$main->SetIcon($icon);

my $font = Win32::GUI::Font->new(
		-name => "Comic Sans MS", 
    -size => 10,
    -bold => 1);

$main->AddLabel(
    -text   => "Date:",
    -font   => $font,
    -left   => 20,
    -top    => 10);
    
my $mm = $main->AddTextfield(
    -name     => "month",
    -tabstop  => 1,
    -left     => 60,
    -top      => 10,
    -width    => 25,
    -height   => 22,
    -tabstop  => 1,
    -foreground => "#000000",
    -background => "#FFFFFF");

$main->AddLabel(
    -text   => "/",
    -left   => 90,
    -font   => $font,
    -top    => 10);

my $dd = $main->AddTextfield(
    -name     => "day",
    -tabstop  => 1,
    -left     => 100,
    -top      => 10,
    -width    => 25,
    -height   => 22,
    -tabstop  => 1,
    -foreground => "#000000",
    -background => "#FFFFFF");

$main->AddLabel(
    -text   => "/",
    -font   => $font,
    -left   => 130,
    -top    => 10);    
    
my $yyyy = $main->AddTextfield(
    -name     => "year",
   	-tabstop  => 1,
    -left     => 140,
   	-top      => 10,
    -width    => 40,
    -height   => 22,
    -tabstop  => 1,
    -foreground => "#000000",
    -background => "#FFFFFF");

$main->AddLabel(
    -text   => "Time:",
    -left   => 200,
    -font   => $font,
    -top    => 10);

my $hr = $main->AddTextfield(
    -name     => "hours",
   	-tabstop  => 1,
    -left     => 240,
   	-top      => 10,
    -width    => 25,
    -height   => 22,
    -tabstop  => 1,
    -foreground => "#000000",
    -background => "#FFFFFF");

$main->AddLabel(
    -text   => ":",
    -left   => 270,
    -font   => $font,
    -top    => 10);

my $min = $main->AddTextfield(
    -name     => "minutes",
   	-tabstop  => 1,
    -left     => 275,
   	-top      => 10,
    -width    => 25,
    -height   => 22,
    -tabstop  => 1,
    -foreground => "#000000",
    -background => "#FFFFFF");

$main->AddLabel(
    -text   => ":",
    -left   => 305,
    -font   => $font,
    -top    => 10);

my $sec = $main->AddTextfield(
    -name     => "seconds",
   	-tabstop  => 1,
    -left     => 310,
   	-top      => 10,
    -width    => 50,
    -height   => 22,
    -tabstop  => 1,
    -foreground => "#000000",
    -background => "#FFFFFF");
    
$main->AddLabel(
    -text   => "Source:",
    -left   => 20,
    -font   => $font,
    -top    => 50);

# http://perl-win32-gui.sourceforge.net/cgi-bin/docs.cgi?doc=combobox
my $combo = $main->AddCombobox(
 -name   => "Combobox",
 -dropdown => 1,
 -vscroll => 1,
 -top    => 50,
 -left   => 80,
 -width  => 100,
 -height => 110,
 -tabstop=> 1,
 );

$combo->SetExtendedUI(1);
$combo->InsertItem("REG");
$combo->InsertItem("EVT");
$combo->InsertItem("DrWtsn");
$combo->InsertItem("IIS");
$combo->InsertItem("INFO2");
$combo->InsertItem("PCAP");
$combo->InsertItem("PREF");

$main->AddLabel(
    -text   => "User:",
    -left   => 200,
    -font   => $font,
    -top    => 50);

my $user = $main->AddTextfield(
    -name     => "user",
   	-tabstop  => 1,
    -left     => 245,
   	-top      => 50,
    -width    => 100,
    -height   => 22,
    -tabstop  => 1,
    -foreground => "#000000",
    -background => "#FFFFFF");  

$main->AddLabel(
    -text   => "Server:",
    -left   => 375,
    -font   => $font,
    -top    => 50);

my $server = $main->AddTextfield(
    -name     => "server",
   	-tabstop  => 1,
    -left     => 430,
   	-top      => 50,
    -width    => 100,
    -height   => 22,
    -tabstop  => 1,
    -foreground => "#000000",
    -background => "#FFFFFF");  

$main->AddLabel(
    -text   => "Descr:",
    -left   => 20,
    -font   => $font,
    -top    => 90);

my $descr = $main->AddTextfield(
    -name     => "descr",
    -tabstop  => 1,
    -left     => 80,
    -top      => 90,
    -width    => 420,
    -height   => 22,
    -tabstop  => 1,
    -foreground => "#000000",
    -background => "#FFFFFF");

$main->AddLabel(
    -text   => "Event File:",
    -font   => $font,
    -left   => 20,
    -top    => 130);
    
my $evtfile = $main->AddTextfield(
    -name     => "evtfile",
    -tabstop  => 1,
    -left     => 100,
    -top      => 130,
    -width    => 300,
    -height   => 22,
    -tabstop  => 1,
    -foreground => "#000000",
    -background => "#FFFFFF");

my $browse = $main->AddButton(
		-name => 'browse',
		-font => $font,
		-left => 435,
		-top  => 130,
		-width => 55,
		-height => 25,
		-tabstop  => 1,
		-text => "Browse");

my $add = $main->AddButton(
		-name => 'add',
		-left => 355,
		-top  => 170,
		-font => $font,
		-width => 55,
		-height => 25,
		-tabstop => 1,
		-text => "Add");
		
$main->AddButton(
		-name => 'close',
		-left => 435,
		-top  => 170,
		-width => 55,
		-height => 25,
		-font  => $font,
		-tabstop => 1,
		-text => "Close");

my $status = new Win32::GUI::StatusBar($main,
		-text  => "Timeline Entry v.".$VERSION." opened.",
);

$main->Show();
Win32::GUI::Dialog();
#-----------------------------------------------------------



#-----------------------------------------------------------
sub browse_Click {
  # Open a file
  my $file = Win32::GUI::GetOpenFileName(
                   -owner  => $main,
                   -title  => "Save to an event file",
                   -filter => [
                       'Report file (*.txt)' => '*.txt',
                       'All files' => '*.*',
                    ],
                   );
  if ($file) {
  	$file = $file."\.txt" unless ($file =~ m/\.\w+$/i);
  	$evtfile->Text($file);

  } elsif (Win32::GUI::CommDlgExtendedError()) {
     $main->MessageBox ("ERROR : ".Win32::GUI::CommDlgExtendedError(),
                        "GetOpenFileName Error");
  }
  0;
}

sub add_Click {	

	my $epoch = createEpoch();
	my $src   = $combo->Text();
	my $u     = $user->Text();
	my $s     = $server->Text();
	my $d     = $descr->Text();
	
	my $evt_str = $epoch."|".$src."|".$s."|".$u."|".$d;
	
	my $f = $evtfile->Text();
	
	if ($f eq "") {
		$status->Text("No filename entered.");
	}
	else {
		open(FH,">>",$f);
		print FH $evt_str."\n";
		close(FH);
		$status->Text($evt_str);
	}
}

sub close_Click {
	exit 1;
}

sub Combobox_CloseUp {
#	$status->Text("Plugin File = ".$combo->GetLBText($combo->GetCurSel()));
	
}


# About box
sub tln_OnAbout {
  my $self = shift;

  $self->MessageBox(
     "Timeline Entry, v.".$VERSION."\r\n".
     "Allow analyst to manually enter timeline data\r\n".
     "\r\n".
     "Date Entry -> MM/DD/YYYY\r\n".
     "Time Entry -> HH:MM:SS[.SS]  GMT\r\n".
     "\r\n".
     "Copyright 2012 Quantum Analytics Research, LLC\r\n".
     "Author: H\. Carvey, keydet89\@yahoo\.com",
     "About...",
     MB_ICONINFORMATION | MB_OK,
  );
  0;
}
#-----------------------------------------------------------

sub createEpoch {
#	my $dt = DateTime->new(year => $yyyy->Text(), 
#												 month => $mm->Text(), 
#												 day => $dd->Text(), 
#                         hour => $hr->Text(), 
#                         minute => $min->Text(), 
#                         second => $sec->Text());                   
#	my $epoch = $dt->epoch;
	my $epoch = timegm($sec->Text(),
	                   $min->Text(),
	                   $hr->Text(), 
	                   $dd->Text(),
	                   ($mm->Text() - 1),
	                   $yyyy->Text());
	return $epoch;
}
