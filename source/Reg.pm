# package Reg.pm
# Author Jolanta Thomassen
# Copyright 2008

# Developped as a part of a dissertation
# submitted to The University of Liverpool
# in partial fulfillment of the requirements
# for the degree of Master of Science (IT security)

#!/usr/bin/perl
package Reg;

use strict;
use Exporter;
use Encode qw/encode decode/;
use vars qw(@ISA @EXPORT);
@ISA = qw(Exporter);
@EXPORT = ();

# Input file functions

sub open_file
{
	my $file = $_[0];
	die "File $file not found.\n" unless (-e $file);
	open(HIVE, $file) || die "Could not open file $file!\n";
	binmode(HIVE);
}

sub file_size
{
	return -s HIVE;
}

sub close_file
{
	close(HIVE);
}

# general functions

sub read_record
{
	my $offset = $_[0];
	my $length = $_[1];
	seek(HIVE, $offset, 0x0);
	read(HIVE, my $record, $length);
	return $record;
}

sub valid_offset
{
	my $offset = $_[0];
	return $offset >= 0x0 && $offset < -s HIVE;
}

sub offset
{
	my $offset = $_[0];
	return unpack("L", read_record($offset, 0x4));
}

sub file_offset
{
	my $offset = $_[0];
	return $offset + 0x1000;
}

sub cell_size
{
	my $offset = $_[0];
	return unpack("l", read_record($offset, 0x4));
}

sub cell_signature
{
	my $offset = $_[0];
	return read_record($offset + 0x4, 0x2);
}

sub signature
{
	my $offset = $_[0];
	return read_record($offset, 0x4)
}

# base block functions

sub file_name
{
	my $record=read_record(0x30, 0x40);
	return $record;
}

sub file_time
{
	return 0xc;
}

sub root_key_offset
{
	return unpack("L", read_record(0x24, 0x4));
}

# bin header functions

sub bin_size
{
	my $offset = $_[0];
	return unpack("L", read_record($offset + 0x8, 0x4));
}

# key cell functions

sub key_type
{
	my $offset = $_[0];
	return unpack("S", read_record($offset + 0x6, 0x2));
}

sub key_time
{
	my $offset = $_[0];
	return $offset + 0x8;
}

sub parent_offset
{
	my $offset = $_[0];
	return unpack("L", read_record($offset + 0x14, 0x4));
}

sub number_of_subkeys
{
	my $offset = $_[0];
	return unpack("L", read_record($offset + 0x18, 0x4));
}

sub subkey_list_offset
{
	my $offset = $_[0];
	return unpack("L", read_record($offset + 0x20, 0x4));
}

sub number_of_values
{
	my $offset = $_[0];
	return unpack("L", read_record($offset + 0x28, 0x4));
}

sub value_list_offset
{
	my $offset = $_[0];
	return unpack("L", read_record($offset + 0x2c, 0x4));
}

sub security_descriptor_offset
{
	my $offset = $_[0];
	return unpack("L", read_record($offset + 0x30, 0x4));
}

sub class_name_offset
{
	my $offset = $_[0];
	return unpack("L", read_record($offset + 0x34, 0x4));
}

sub max_sub_key_name_length
{
	my $offset = $_[0];
	return unpack("L", read_record($offset + 0x38, 0x4));
}

sub max_sub_key_class_size
{
	my $offset = $_[0];
	return unpack("L", read_record($offset + 0x3c, 0x4));
}

sub max_value_name_length
{
	my $offset = $_[0];
	return unpack("L", read_record($offset + 0x40, 0x4));
}

sub max_value_data_size
{
	my $offset = $_[0];
	return unpack("L", read_record($offset + 0x44, 0x4));
}


sub key_name_length
{
	my $offset = $_[0];
	return unpack("S", read_record($offset + 0x4c, 0x2));
}

sub class_name_length
{
	my $offset = $_[0];
	return unpack("S", read_record($offset + 0x4e, 0x2));
}

sub key_name
{
	my $offset = $_[0];
	my $length = $_[1];
	return read_record($offset + 0x50, $length);
}

# class name cell functions

sub class_name
{
	my $offset = $_[0];
	my $length = $_[1];
	return read_record(file_offset(class_name_offset($offset)) + 0x4, $length);
}

# sub key list cell functions

sub sublist_number_of_subkeys
{
	my $offset = $_[0];
	return unpack("S", read_record($offset + 0x6, 0x2));
}

# value cell functions

sub data_type
{
	my $offset = $_[0];
	return unpack("C", read_record($offset + 0xb, 0x1));
}

sub value_type
{
	my $offset = $_[0];
	return unpack("L", read_record($offset+0x10, 0x4));
}

sub named_value
{
	my $offset = $_[0];
	return unpack("S", read_record($offset+0x14, 0x2));
}

sub value_name_length
{
	my $offset = $_[0];
	return unpack("S", read_record($offset+0x6, 0x2));
}

sub value_name
{
	my $offset = $_[0];
	my $length = $_[1];
	return read_record($offset+0x18, $length);
}
sub value_data_offset
{
	my $offset = $_[0];
	return $offset + 0xc;
}

sub value_data_length
{
	my $offset = $_[0];
	return unpack("S", read_record($offset+0x8, 2));
}

sub value_data
{
	my $offset = $_[0];
	my $length = $_[1];
	return read_record(value_data_offset($offset), $length) ;
}

sub linked_value_data
{
	my $offset = $_[0];
	return read_record(file_offset(offset(value_data_offset($offset)))+4, value_data_length($offset));
}

# translation functions

sub binary
{
	my $data=$_[0];
	my $str = unpack("H*",$data);
	my $binary_data="";
	for (my $i = 0; $i < length($str); $i += 0x2)
	{
		$binary_data .= " " unless $binary_data eq "";
		$binary_data .= substr($str, $i, 0x2);
	}
	return $binary_data;
}

sub dump
{
	my $data=$_[0];
	my $binary=Reg::binary($data);
	my $output="";
	for (my $i=0; $i<=length($binary); $i=$i+48)
	{
		$output.= "\n" . pack("A48",substr($binary, $i, 48)) . "" . pack("A16",substr(Reg::safe_chars($data), $i/3, 0x10));
	}
	return $output;
}

sub unicode
{
	my $string=$_[0];
	# in unicode strings every other character is x00
	# additionally control characters are removed to preserve formatting of output
	$string =~ s/[\x00-\x19]//g;
	return $string;
}

sub safe_chars
{
	my $string=$_[0];
	# replaces all non basic characters in hex dump with dots
	$string =~ s/[^\x21-\x7e]/./g;
	return $string;
}

sub rot13
{
	my $string=$_[0];
	$string =~ tr/N-ZA-Mn-za-m/A-Za-z/ if $string =~ m/^HRZR/;
	return $string;
}

sub timestamp
{
	my $offset = $_[0];
	# borrowed from Dan Sully's package Audio::WMA
	# http://search.cpan.org/src/DANIEL/Audio-WMA-1.1/WMA.pm
	my $timestamp =time_high($offset) * 0x2 ** 0x20 + time_low($offset);
	return int(($timestamp - 116444736000000000) / 10000000);
}

sub time_high
{
	my $offset = $_[0];
	return unpack("L", read_record($offset + 0x4, 0x4));
}

sub time_low
{
	my $offset = $_[0];
	return unpack("L", read_record($offset, 0x4));
}

1;
