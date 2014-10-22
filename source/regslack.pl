# Script regslack.pl
# Author Jolanta Thomassen
# Copyright 2008

# Developped as a part of a dissertation
# submitted to The University of Liverpool
# in partial fulfillment of the requirements
# for the degree of Master of Science (IT security)

#!/usr/bin/perl

use strict;
use warnings;
use Reg;

my %regtype = (
	0 => 'REG_NONE',
	1 => 'REG_SZ',
	2 => 'REG_EXPAND_SZ',
	3 => 'REG_BINARY',
	4 => 'REG_DWORD',
	5 => 'REG_DWORD_BIG_ENDIAN',
	6 => 'REG_LINK',
	7 => 'REG_MULTI_SZ',
	8 => 'REG_RESOURCE_LIST',
	9 => 'REG_FULL_RESOURCE_DESCRIPTION',
	10=> 'REG_RESSOURCE_REQUIREMENT_MAP',
	11=> 'REG_QWORD',);

my $file = shift || die "Enter a filename.\n";
Reg::open_file($file);

# hash to store names and offsets of all live keys
my %live_key = ();

# hash to store offsets and sizes of allocated space
my %allocated=();

# hash to store offsets and sizes of unallocated space
my %unallocated=();

# marks base block as allocated
$allocated{0} = 0x1000;

# marks bin headers as allocated
my $offset=0x1000;
while ($offset < Reg::file_size)
{
	if (Reg::signature($offset) eq "hbin")
	{
		$allocated{$offset} = 0x20;
	}
	$offset+=0x1000;
}

# makes sure that the last part of the file will be included in the unallocated space
$allocated{Reg::file_size()} = 0;

# initialize all counters
my $rejected_keys=0x0;
my $rejected_values=0x0;
my $recovered_keys=0x0;
my $recovered_values=0x0;
my $recovered_keys_allocated_space=0x0;
my $recovered_values_allocated_space=0x0;

# parses the tree to identify allocated cells
parse_registry_tree(parse_base_block(),"");

# calculate unallocated space from allocated space
my $previous_offset=0;
foreach my $current_offset(sort{$a <=> $b }(keys (%allocated)))
{
	if ($previous_offset < $current_offset)
	{
		$unallocated{$previous_offset} = $current_offset-$previous_offset;
	}
	$previous_offset=$current_offset + $allocated{$current_offset};
}

my @slack = sort{$a <=> $b }(keys %unallocated);

# diplays cells with negative sizes found in unallocated space
#foreach my $cell_offset (@slack)
#{
#	if (Reg::cell_size($cell_offset) <= 0)
#	{
#		printf "Offset: 0x%x - 0x%x, size %d\n ", $cell_offset, $cell_offset + $unallocated{$cell_offset}, Reg::cell_size($cell_offset);
#		print Reg::dump(Reg::read_record($cell_offset,$unallocated{$cell_offset})) . "\n\n";
#	}
#}

# look for keys in unallocated cells
foreach my $cell_offset (@slack) 
{
	if ($unallocated{$cell_offset} > 80)
	{
		my $offset=$cell_offset;
		# stop reading when the remaining space is too small to hold a key.
		my $max_offset = $cell_offset + $unallocated{$cell_offset} - 80;
		while ($offset < $max_offset)
		{
			if (Reg::cell_signature($offset) eq "nk")
			{
				my $allocated_space = (Reg::cell_size($cell_offset)<0);
				parse_key($offset, $offset + $unallocated{$cell_offset}, $allocated_space);
			}
			$offset+=8;
		}
	}
}

print "\nRecovered $recovered_keys keys and $recovered_values values: #$recovered_keys_allocated_space keys from allocated space.\n";
print "\nRejected $rejected_keys keys and $rejected_values values.\n";

print "\n### Unallocated Space ###\n";
foreach my $cell_offset (@slack)
{
	# cells of size 0x8 are too small to hold interesting data
	if ($unallocated{$cell_offset} > 0x8)
	{
	my $offset=$cell_offset;
	my $cell_size=$unallocated{$cell_offset};
	printf "\nOffset 0x%x - 0x%x: ", $cell_offset, $cell_offset+$cell_size;
	# for efficiency reason hex data is split into small units
	while ($cell_size >= 16)
	{
		print Reg::dump(Reg::read_record($cell_offset, 16)) ;
		$cell_offset+=16;
		$cell_size-=16;
	}
	if ($cell_size > 0)
	{
		print Reg::dump(Reg::read_record($cell_offset, $cell_size)) ;
	}
	print "\n";
	}
}


Reg::close_file();

sub parse_base_block

# Parses base block (first 0x1000 bytes) of a hive file.
# Extracts file name, timestamp and offset.
# Fails if signature, file size, file name or timestamp are invalid (corrupted hive).
# Returns offset to root key.

{
	die "Corrupted hive." unless Reg::file_size % 4096 == 0 && Reg::signature(0) eq "regf";
	print "\"" . Reg::unicode(Reg::file_name()) ."\"\n";
	print "[" . gmtime(Reg::timestamp(Reg::file_time())) . "]\n";
	return Reg::root_key_offset();
}

sub parse_registry_tree

# Parses recursively down the registry tree in a preorder manner.
# Arguments: offset to current tree node and previous key path.
# Fails if the current node is not a key or a sub key list.

{
	my $offset=Reg::file_offset($_[0]);
	my $key_path=$_[1];
	my $signature = Reg::cell_signature($offset);
	if ($signature eq "nk")
	{
		parse_live_key($offset, $key_path);
	}
	elsif (($signature eq "lf") || ($signature eq "lh") || ($signature eq "ri") ||($signature eq "li"))
	{
		parse_live_subkey_list($offset, $key_path, $signature);
	}
	else
	{
		die "Unknown node $signature found at offset $offset.";
	}
}

sub parse_live_key

# Parses registry key.
# Marks all cells refered by a key as allocated.
# Saves key names and offsets to all live keys.
{
	my $offset = $_[0];
	my $key_path = $_[1];

	# mark key cell as allocated
	$allocated{$offset} = abs(Reg::cell_size($offset));

	$key_path .= "\\"if $key_path;
	$key_path .=Reg::key_name($offset, Reg::key_name_length($offset));

	$live_key{$key_path} = $offset;

	# mark class name as allocated
	my $classname_offset=Reg::class_name_offset($offset);
	$allocated{Reg::file_offset($classname_offset)}= abs(Reg::cell_size(Reg::file_offset($classname_offset))) unless ($classname_offset == 0xffffffff);

	# mark security descriptor cell as allocated
	my $security_descriptor_offset = Reg::security_descriptor_offset($offset);
	$allocated{Reg::file_offset($security_descriptor_offset)}= abs(Reg::cell_size(Reg::file_offset($security_descriptor_offset))) unless ($security_descriptor_offset == 0xffffffff);

	# mark value list cell as allocated
	my $value_list_offset = Reg::value_list_offset($offset);
	$allocated{Reg::file_offset($value_list_offset)}= abs(Reg::cell_size(Reg::file_offset($value_list_offset))) unless ($value_list_offset == 0xffffffff);

	my $number_of_values=Reg::number_of_values($offset);
	for(my $value = 1; $value <= $number_of_values; $value++)
	{
		my $value_offset = Reg::file_offset(Reg::offset(Reg::file_offset($value_list_offset) + ($value * 4)));
		# mark value cell as allocated
		$allocated{$value_offset}= abs(Reg::cell_size($value_offset));

		if (Reg::data_type($value_offset) != 0x80)
		{
			my $value_data_offset=Reg::file_offset(Reg::offset(Reg::value_data_offset($value_offset)));
			# mark value data cell as allocated
			$allocated{$value_data_offset}= abs(Reg::cell_size($value_data_offset));
		}
	}
	parse_registry_tree(Reg::subkey_list_offset($offset), $key_path) unless Reg::number_of_subkeys($offset) == 0;
}

sub parse_live_subkey_list
# Parses sub key list.
# Marks all sub key list cells as allocated.

{
	my $offset=$_[0];
	my $key_path=$_[1];
	my $signature=$_[2];

	# mark subkey list cell as allocated
	$allocated{$offset} = abs(Reg::cell_size($offset));

	my $number_of_subkeys = Reg::sublist_number_of_subkeys($offset);
	$offset += 4 if ($signature eq "ri") || ($signature eq "li");
	for(my $key=1; $key <= $number_of_subkeys; $key++)
	{
		$offset += 4;
		$offset += 4 if ($signature eq "lf") || ($signature eq "lh");
		parse_registry_tree(Reg::offset($offset),$key_path);
	}
}

sub parse_key

# Recovers registry key from unallocated space.
# Returns if any key field is invalid.
# Reconstructs key path by following parent links.
# Outputs key name, offset, timestamp and number of values.
# Outputs same data if a "live" key with the same name is found.
{
	my $offset = $_[0];
	my $max_offset = $_[1];
	my $allocated_space = $_[2];

	# data that is used more than once is stored in variables
	my $key_name_length=Reg::key_name_length($offset);
	my $key_time = Reg::key_time($offset);
	my $timestamp = Reg::timestamp($key_time);
	my $parent_offset = Reg::parent_offset($offset);
	my $key_type= Reg::key_type($offset);
	my $class_name_offset = Reg::class_name_offset($offset);
	my $class_name_length = Reg::class_name_length($offset);
	my $number_of_values = Reg::number_of_values($offset);
	my $value_list_offset = Reg::value_list_offset($offset);
	my $max_value_name_length = Reg::max_value_name_length($offset);
	my $key_name=Reg::key_name($offset, Reg::key_name_length($offset));

	# key validation (returns if data is corrupted)
	if ($offset + Reg::key_name_length($offset) > $max_offset
	|| !gmtime $timestamp
	|| (gmtime $timestamp && $timestamp > Reg::timestamp(Reg::file_time()))
	|| !Reg::valid_offset($parent_offset)
	|| Reg::number_of_subkeys($offset)!= 0x0
	|| Reg::subkey_list_offset($offset) != 0xffffffff
	|| Reg::security_descriptor_offset($offset) != 0xffffffff
	|| ($class_name_offset != 0xffffffff && $class_name_length == 0x0)
	|| ($class_name_offset == 0xffffffff && $class_name_length != 0x0)
	|| $key_name_length == 0x0
	|| $key_name_length > 0xff
	|| ($number_of_values == 0x0 && ($value_list_offset != 0xffffffff || $max_value_name_length != 0x0 || Reg::max_value_data_size($offset) != 0x0))
	|| ($number_of_values > 0x0 && (!Reg::valid_offset($value_list_offset) || $max_value_name_length > 0x3ff)))
 	{
		$rejected_keys++;
#		print "Key: [";
#		print "" . gmtime $timestamp if gmtime $timestamp;
#		print "] " . Reg::safe_chars($key_name) . "\n";
		return;
	}

	$recovered_keys++;

	# backtrack via parent links to recover full key key path
	my $key_path=$key_name;
	$parent_offset = Reg::file_offset($parent_offset);
	while (Reg::valid_offset($parent_offset) && Reg::cell_signature($parent_offset) eq "nk")
	{
		$key_path = Reg::key_name($parent_offset, Reg::key_name_length($parent_offset)) . "\\". $key_path ;
		$key_type=Reg::key_type($parent_offset);
		$parent_offset=Reg::file_offset(Reg::parent_offset($parent_offset));
	}
	# insert question marks if full path could not be retrieved
	$key_path="???\\" . $key_path unless $key_type eq 0x2c || $key_type eq 0xac;

	if (exists $live_key{$key_path}) { print "\n### Updated Key "; }
	else { print "\n### Deleted Key "; }

	# indicates if key was found in a cell with a negative size
	if ($allocated_space)
	{
		$recovered_keys_allocated_space++;
		print "(in Allocated Space)";
	}
	print " ###\n\n";

	# display key data
	print "$key_path\n";
	printf "Offset: 0x%x ", $offset;
	print "[" . gmtime(Reg::timestamp(Reg::key_time($offset))) . "]\n";
	print "Number of values: " . $number_of_values . "\n";
	parse_value_list($offset, $number_of_values) unless $value_list_offset == 0xffffffff || $number_of_values == 0;

	if (exists $live_key{$key_path})
	{
		# display live key data
		my $live_offset=$live_key{$key_path};
		print "\nCorresponding Live Key:\n";
		printf "Offset: 0x%x ", $live_offset;
		print "[" . gmtime(Reg::timestamp(Reg::key_time($live_offset))) . "]\n";
		print "Number of values: " . Reg::number_of_values($live_offset) . "\n";
		parse_value_list($live_key{$key_path}, Reg::number_of_values($live_key{$key_path})) unless Reg::value_list_offset($live_key{$key_path}) == 0xffffffff || Reg::number_of_values($live_key{$key_path}) == 0;
 	}
}

sub parse_value_list

# Parses value list cell.
{
	my $offset = $_[0];
	my $number_of_values = $_[1];
	my $value_list_offset = Reg::file_offset(Reg::value_list_offset($offset));
	for(my $value = 1; $value <= $number_of_values; $value++)
	{
		my $value_offset=Reg::file_offset(Reg::offset($value_list_offset + $value * 0x4));
		parse_key_value($value_offset) if Reg::valid_offset($value_offset);
	}
}

sub parse_key_value

# Parses value cell.
# Returns if any value field is invalid.
# Outputs value offset, name, type and translated value data.

{
	my $offset = $_[0];

	# value validation
	my $value_name_length = Reg::value_name_length($offset);
	my $data_type = Reg::data_type($offset);
	my $named_value = Reg::named_value($offset);

	#return if any value field is invalid
	# to output rejected values this code must be moved to after value data computation
	if (Reg::cell_signature($offset) ne "vk"
	|| $value_name_length > 0x3ff
	|| ($data_type != 0x0 && $data_type != 0x80)
	|| ($data_type == 0x0 && !Reg::valid_offset(Reg::file_offset(Reg::offset(Reg::value_data_offset($offset)))))
	|| ($named_value == 0x0 && $value_name_length > 0x0)
	|| ($named_value != 0x0 && $value_name_length == 0x0))
 	{
#		$rejected_values++;
#		print "Value: " . Reg::value_type($offset) . "; " . Reg::safe_chars(Reg::value_name($offset, Reg::value_name_length($offset))) . "; " . Reg::safe_chars($value_data) ."\n";
		return;
	}

	$recovered_values++;

	my $value_type = Reg::value_type($offset);
	$value_type = $regtype{$value_type} if defined $regtype{$value_type};

	my $value_name="";
	if (Reg::named_value($offset))
	{
		$value_name=Reg::rot13(Reg::value_name($offset, $value_name_length));
	}
	else
	{
		$value_name = "Default";
	}

	my $value_data = "";
	my $value_data_length = Reg::value_data_length($offset);
	if ($value_data_length > 0)
	{
		if ($data_type == 0x80)
		{
			$value_data = Reg::value_data($offset, Reg::value_data_length($offset));
		}
		else
		{
			$value_data = Reg::linked_value_data($offset, Reg::value_data_length($offset));
		}

		if (($value_type eq "REG_SZ")||($value_type eq "REG_EXPAND_SZ")||($value_type eq "REG_LINK"))
		{
			$value_data=Reg::unicode($value_data);
		}
		elsif ($value_type eq "REG_MULTI_SZ")
		{
			$value_data=Reg::unicode(join("; ",split(/\x00\x00/, substr($value_data,0,$value_data_length-1))));
		}
		elsif ($value_type eq "REG_DWORD")
		{
			$value_data= unpack("L", $value_data);
		}
		elsif ($value_type eq "REG_DWORD_BIG_ENDIAN")
		{
			$value_data= unpack("N", $value_data);
		}
		elsif ($value_type eq "REG_QWORD")
		{
			$value_data= Reg::binary($value_data);
		}
		else
		{
			$value_data= Reg::dump($value_data);
		}
	}

	printf "Offset: 0x%x ", $offset;
	print "-->$value_type; $value_name; $value_data\n";
}
