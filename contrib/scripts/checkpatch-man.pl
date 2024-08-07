#!/usr/bin/env perl
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2024, DataDirect Networks, Inc.
# Author: Frederick Dilger <fdilger@whamcloud.com>
#
# Attributed to:
# (c) 2001, Dave Jones. (the file handling bit)
# (c) 2005, Joel Schopp <jschopp@austin.ibm.com> (the ugly bit)
# (c) 2007,2008, Andy Whitcroft <apw@uk.ibm.com> (new conditions, test suite)
# (c) 2008-2010 Andy Whitcroft <apw@canonical.com>
# (c) 2010-2018 Joe Perches <joe@perches.com>
# for their work in 'checkpatch.pl'

use strict;
use warnings;
use POSIX;
use File::Basename;
use Cwd 'abs_path';
use Term::ANSIColor qw(:constants);
use Encode qw(decode encode);

my $P = $0;
my $D = dirname(abs_path($P));

my $V = '0.32';

use Getopt::Long qw(:config no_auto_abbrev);

my $file = 0;
my $gitroot = $ENV{'GIT_DIR'};
$gitroot = ".git" if !defined($gitroot);
my %use_type = ();
my $configuration_file = ".checkpatch.conf";
my $max_line_length = 80;
my $ignore_perl_version = 0;
my $minimum_perl_version = 5.10.0;
my $spelling_file = "$D/spelling-man.txt";
my $color = "auto";
my $git_command ='export LANGUAGE=en_US.UTF-8; git';

sub help {
	my ($exitcode) = @_;

	print << "EOM";
Usage: $P [OPTION]... [FILE]...
Version: $V

Options:
  -q, --quiet                quiet
  --no-checks                do not show CHECK messages
  -h, --help                 display this help and exit
When FILE is - read standard input.
EOM

	exit($exitcode);
}

my $quiet = 0;
my $check = 1;
my $help = 0;

my $conf = which_conf($configuration_file);
if (-f $conf) {
	my @conf_args;
	open(my $conffile, '<', "$conf")
	    or warn "$P: Can't find a readable $configuration_file file $!\n";

	while (<$conffile>) {
		my $line = $_;

		$line =~ s/\s*\n?$//g;
		$line =~ s/^\s*//g;
		$line =~ s/\s+/ /g;

		next if ($line =~ m/^\s*#/);
		next if ($line =~ m/^\s*$/);

		my @words = split(" ", $line);
		foreach my $word (@words) {
			last if ($word =~ m/^#/);
			push (@conf_args, $word);
		}
	}
	close($conffile);
	unshift(@ARGV, @conf_args) if @conf_args;
}

GetOptions(
	'q|quiet+'	=> \$quiet,
	'c|checks!'	=> \$check,
	'h|help'	=> \$help,
) or $help = 2;

# $help is 1 if either -h, --help or --version is passed as option - exitcode: 0
# $help is 2 if invalid option is passed - exitcode: 1
help($help - 1) if ($help);

if ($color =~ /^[01]$/) {
	$color = !$color;
} elsif ($color =~ /^always$/i) {
	$color = 1;
} elsif ($color =~ /^never$/i) {
	$color = 0;
} elsif ($color =~ /^auto$/i) {
	$color = (-t STDOUT);
} else {
	die "$P: Invalid color mode: $color\n";
}

my $exit = 0;

my $perl_version_ok = 1;
if ($^V && $^V lt $minimum_perl_version) {
	$perl_version_ok = 0;
	printf "$P: requires at least perl version %vd\n", $minimum_perl_version;
	exit(1) if (!$ignore_perl_version);
}

#if no filenames are given, push '-' to read patch from stdin
if ($#ARGV < 0) {
	push(@ARGV, '-');
}

sub edit_distance_min {
	my (@arr) = @_;
	my $len = scalar @arr;
	if ((scalar @arr) < 1) {
		# if underflow, return
		return;
	}
	my $min = $arr[0];
	for my $i (0 .. ($len-1)) {
		if ($arr[$i] < $min) {
			$min = $arr[$i];
		}
	}
	return $min;
}

sub get_edit_distance {
	my ($str1, $str2) = @_;
	$str1 = lc($str1);
	$str2 = lc($str2);
	$str1 =~ s/-//g;
	$str2 =~ s/-//g;
	my $len1 = length($str1);
	my $len2 = length($str2);
	# two dimensional array storing minimum edit distance
	my @distance;
	for my $i (0 .. $len1) {
		for my $j (0 .. $len2) {
			if ($i == 0) {
				$distance[$i][$j] = $j;
			} elsif ($j == 0) {
				$distance[$i][$j] = $i;
			} elsif (substr($str1, $i-1, 1) eq substr($str2, $j-1, 1)) {
				$distance[$i][$j] = $distance[$i - 1][$j - 1];
			} else {
				my $dist1 = $distance[$i][$j - 1]; #insert distance
				my $dist2 = $distance[$i - 1][$j]; # remove
				my $dist3 = $distance[$i - 1][$j - 1]; #replace
				$distance[$i][$j] = 1 + edit_distance_min($dist1, $dist2, $dist3);
			}
		}
	}
	return $distance[$len1][$len2];
}

# Load common spelling mistakes and build regular expression list.
if (open(my $spelling, '<', $spelling_file)) {
	while (<$spelling>) {
		my $line = $_;

		$line =~ s/\s*\n?$//g;
		$line =~ s/^\s*//g;

		next if ($line =~ m/^\s*#/);
		next if ($line =~ m/^\s*$/);
	}
	close($spelling);
} else {
	warn "No typos will be found - file '$spelling_file': $!\n";
}

sub git_is_single_file {
	my ($filename) = @_;

	return 0 if ((which("git") eq "") || !(-e "$gitroot"));

	my $output = `${git_command} ls-files -- $filename 2>/dev/null`;
	my $count = $output =~ tr/\n//;
	return $count eq 1 && $output =~ m{^${filename}$};
}


my @rawlines = ();
my @lines = ();

my $vname;
for my $filename (@ARGV) {
	my $FILE;
	my $is_git_file = git_is_single_file($filename);
	my $oldfile = $file;
	$file = 1 if ($is_git_file);
	if ($filename eq '-') {
		open($FILE, '<&STDIN');
	} else {
# 		remove a/ or b/ from git diff files
		$filename =~ s/^[ab]\///;
		open($FILE, '<', $filename) ||
			die "$P: $filename: open failed - $!\n";
	}
	if ($filename eq '-') {
		$vname = 'Your patch';
	} else {
		$vname = $filename;
	}
	while (my $line = readline($FILE)) {
		push(@rawlines, $line);
	}
	close($FILE);

# process man pages differently
	if (!process($filename)) {
		$exit = 1;
	}
	@rawlines = ();
	@lines = ();
	$file = $oldfile if ($is_git_file);
}

if (!$quiet) {
	if (!$perl_version_ok) {
		print << "EOM"

NOTE: perl $^V is not modern enough to detect all possible issues.
      An upgrade to at least perl $minimum_perl_version is suggested.
EOM
	}
	if ($exit) {
		print << "EOM"

NOTE: If any of the errors are false positives, please report
      them to the maintainer, see CHECKPATCH in MAINTAINERS.
EOM
	}
}

exit($exit);

sub which {
	my ($bin) = @_;

	foreach my $path (split(/:/, $ENV{PATH})) {
		if (-e "$path/$bin") {
			return "$path/$bin";
		}
	}

	return "";
}

sub which_conf {
	my ($conf) = @_;

	foreach my $path (split(/:/, ".:$ENV{HOME}:.scripts")) {
		if (-e "$path/$conf") {
			return "$path/$conf";
		}
	}

	return "";
}

my $prefix = '';

sub report {
	my ($level, $type, $msg) = @_;

	my $output = '';
	if ($color) {
		if ($level eq 'ERROR') {
			$output .= RED;
		} elsif ($level eq 'WARNING') {
			$output .= YELLOW;
		} else {
			$output .= GREEN;
		}
	}
	$output .= $prefix . $level . ':';
	$output .= RESET if ($color);
	$output .= ' ' . $msg . "\n";

	push(our @report, $output);

	return 1;
}

sub report_dump {
	our @report;
}

sub ERROR {
	my ($type, $msg) = @_;

	if (report("ERROR", $type, $msg)) {
		our $clean = 0;
		our $cnt_error++;
		return 1;
	}
	return 0;
}
sub WARN {
	my ($type, $msg) = @_;

	if (report("WARNING", $type, $msg)) {
		our $clean = 0;
		our $cnt_warn++;
		return 1;
	}
	return 0;
}
sub CHK {
	my ($type, $msg) = @_;

	if ($check && report("CHECK", $type, $msg)) {
		our $clean = 0;
		our $cnt_chk++;
		return 1;
	}
	return 0;
}

sub get_subject_version {
	my ($subject) = @_;
	my $search_file = 'lustre/utils/';
	my $function_file = 'lustre/';
	my $search_str = $subject;
	my $function_regex = '';
	my $git_log = '';
	my $git_hash = '';
	my $git_describe = '';
	my $pretty_stuff = '';

	for ($subject) {
		if (/lctl/) {
			$search_file .= 'lctl.c';
			$function_file .= 'utils/obdctl.h';
			last;
		}
		if (/lfs/) {
			$search_file .= 'lfs.c';
			$function_file .= 'utils/lfs.c';
			last;
		}
		if (/llapi/) {
			$search_file = 'lustre/include/lustre/lustreapi.h';
			$function_file .= 'lustreapi.h';
			last;
		}
		else {
			$search_file = '';
		}
	}

	$search_str =~ s/\...?$//;
	if ($search_str =~ /^(lctl|lfs)[\-\_].+/) {
		$search_str =~ s/^.*?[\-\_]//;
	}
	$function_regex = $search_str;
	$search_str =~ s/\-/ /g;
	$function_regex =~ s/[\-\_]/\.\*/g;

# anything containing llapi should be an actual function
# having the command as a string might be useful for viewing the command
	if ($search_file) {
		if ($subject =~ /llapi/) {
			$git_log = "git log -L:$function_regex:$function_file 2>/dev/null || git log -L:$function_regex:$search_file 2>/dev/null";
		} else {
			$git_log = "git log -L:$function_regex:$function_file 2>/dev/null || git log -S '$search_str' $search_file";
		}
	}
	my $log = `$git_log`;
	if (! $search_file || ! $log) {
		$git_log = "git log -S '$search_str'";
		print "Doing long search for AVAILABILITY version: $git_log\n";
	}

	$git_hash = "awk '/^commit /{print \$2}' <<< \"\$($git_log)\" | tail -1";
	my $hash = `$git_hash`;
	$hash =~ s/\n$//;
	return "'$subject'\tno git commit hash found: $git_log" if (! $hash);

	$git_describe = "git describe $hash 2>/dev/null || git describe --tags $hash 2>/dev/null || git describe --contains $hash";
	my $version = `$git_describe`;
	$version =~ s/\n$//;

	return "'$subject'\t< $version\t- ".`head -c10 <<< $hash`." no match found" if ($version =~ /\~/);
	return "'$subject'\t  $version\t- ".`head -c10 <<< $hash`;
}

my @standard_headers;

sub find_section_header {
	my ($section_header) = @_;
	my $min_distance = -1;
	my $best_match = '';
	foreach my $header (@standard_headers) {
		my $distance = get_edit_distance($section_header, $header);
		return $header if ($distance == 0);
		if ($distance < $min_distance || $min_distance < 0) {
			$min_distance = $distance;
			$best_match = $header;
		}
	}

	return $best_match if ($min_distance <= 3);
	return "";
}

# used to following pages as reference for style rules
# https://man7.org/linux/man-pages/man7/man-pages.7.html
# https://liw.fi/manpages/
sub process {
	my $filepath = shift;
	$filepath =~ /.*\/(\S+\.([1-8]))$/;
	my $filename = $1;
	my $section_number = $2;
	my $linecnt=0;
	my $prevline="";
	my $prevlinenr=0;
	my $prevrawline="";
	my $stashline="";
	my $stashrawline="";

	@standard_headers = ('NAME', 'LIBRARY', 'SYNOPSIS', 'CONFIGURATION',
		'DESCRIPTION', 'OPTIONS', 'EXIT STATUS', 'RETURN VALUE', 'ERRORS',
		'ENVIRONMENT', 'FILES', 'ATTRIBUTES', 'VERSIONS', 'HISTORY', 'NOTES',
		'CAVEATS', 'BUGS', 'EXAMPLES', 'AUTHORS', 'AVAILABILITY', 'SEE ALSO');
	my $valid_header_order = 1;

	my $subjectline = '';

	our $clean = 1;
	our @report = ();
	our $cnt_lines = 0;
	our $cnt_error = 0;
	our $cnt_warn = 0;
	our $cnt_chk = 0;

	# Trace the real file/line as we go.
	my $linenr = 0;

	# Pre-scan the patch sanitizing the lines.
	my $line;
	foreach my $rawline (@rawlines) {
		$linecnt++;
		$line = $rawline;

# Remove diff marker
		if ($rawline =~ /^[+-]\s?(.*)/) {
			$line = $1;
		}
		push(@lines, $line);
	}

	my $avail_has_release = 0;
	my $avail_has_commit = 0;
	my $avail_has_inclusion = 0;
	$prefix = '';

	my $llapi = ($filename =~ /llapi/i)? 1 : 0;
	my $see_also_done_refs = 0;

	my $curr_header = '';
	my @remaining_headers = @standard_headers;
	foreach my $line (@lines) {
		$prevlinenr = $linenr;
		$linenr++;
		my @linewds = split(" ", $line); #list of words in the line
		my $length = length($line) - 1; #do not count '\n'
		my $rawline = $rawlines[$linenr - 1];

		# Track the previous line.
		($prevline, $stashline) = ($stashline, $line);
		($prevrawline, $stashrawline) = ($stashrawline, $rawline);

		# Set the current file location for messages
		my $herecurr = "#$linenr: FILE: $filepath:$linenr:\n$rawline";
		my $hereprev = "#$prevlinenr: FILE: $filepath:$prevlinenr:\n$prevrawline$rawline";

		$cnt_lines++;

# check for shared object link
		if ($line =~ /^\.so (.*\/)?(.*\.([1-8]))$/) {
			if (! -e "lustre/doc/$2") {
				ERROR("SHARED_OBJECT_PATH",
				      "The file that .so is referencing '$2' is not a valid man page\n" . $herecurr);
			}
			if ($1 !~ /^man[1-8]\/$/) {
				WARN("SHARED_OBJECT_MISSING",
				     "Man page should be preceded by 'man$3/' but was '$1'\n" . $herecurr);
			}
			if ($linecnt != 1) {
				ERROR("SHARED_OBJECT_LINES",
				      "When .so to link to another man page it must be the first and only line\n" . $herecurr);
			}
			next;
		}

# check for blank lines
		if ($line !~ /\S/) {
			WARN("EMPTY_LINE",
			      "Do not use empty lines, prefer .P or .IP for paragraphs or remove the empty line\n" . $herecurr);
		}

# check for lines starting with "..." (probably a mistake)
		if ($line =~ /^\.\.\./) {
			WARN("BAD_FORMATTED_ELLIPSES",
			     "The ellipses will not be well formatted as '...', either put it on the previous line or use '\\&...'\n" . $herecurr);
		}


# check line length
		if ($length > $max_line_length) {
			CHK("LONG_LINE",
			    "Line length of $length exceeds $max_line_length columns\n" . $herecurr);
		}

# check if \f is being used to format man pages
		if ($line =~ /\\f[BIR]/) {
			if ($prevline =~ /^\.TP/) {
				CHK("ESCAPE_SEQUENCE_AFTER_TP",
				    "IGNORE THIS CHECK. Avoid using \\f[BIR] for formatting purposes, however \\c is not supported when following .TP in groff 1.22.3 or older\n" . $hereprev);
			} else {
				WARN("AVOID_ESCAPE_SEQUENCE",
				     "Avoid using \\f[BIR] for formatting purposes, instead use .[BI] or .[BIR][BIR] on a new line. Use \\c at the end of the previous line to use a different format without a space.\n" . $herecurr);
			}
		}

# check for proper \c usage
		if ($prevline =~ /\\c/) {
			if ($prevline !~ /\\c$/) {
				ERROR("LINE_CONTINUATION_PLACEMENT",
				      "'\\c' should only appear at the end of a line\n" . $hereprev);
			} elsif (($prevline =~ /^\.R?BR?/ && $line =~ /^\.R?BR?/) ||
				     ($prevline =~ /^\.R?IR?/ && $line =~ /^\.R?IR?/)) {
				CHK("LINE_CONTINUATION_USAGE",
				    "There is no obvious text style change that would require '\\c', use '\\' if it simply needs a line continuation\n" . $hereprev);
			}
		}
# check for valid macros
		if ($line =~ /^\.([A-Z]+)\b/ &&
		    !($1 =~ /^B[IR]?$/ || $1 =~ /^E[EX]$/ || $1 =~ /^I[BPR]?$/ ||
		      $1 =~ /^LP$/ || $1 =~ /^M[ERT]$/ || $1 =~ /^P[P]?$/ ||
		      $1 =~ /^R[BEIS]$/ || $1 =~ /^S[HMSY]$/ || $1 =~ /^T[HPQ]$/ ||
		      $1 =~ /^U[ER]$/ || $1 =~ /^YS$/)) {
			WARN("NON_STANDARD_MACRO",
			     "'.$1' is not defined in the standard macro library\n" . $herecurr);
		}

# check that the title line is correct
		if ($line =~ /^\.TH/) {
# check title
			if ($filename !~ /^$linewds[1]/i) {
				$linewds[1] =~ /(.*)/;
				WARN("TITLE_FORMAT_FILENAME",
				     "title '$1' does not match the filename\n" . $herecurr);
			}
			if ($linewds[1] =~ /[a-z]/) {
				WARN("TITLE_FORMAT_CAPS",
				     "title must be writen in all CAPS\n" . $herecurr);
			}
# check section number
			if ($linewds[2] !~ /$section_number/) {
				$linewds[2] =~ /(.*)/;
				WARN("TITLE_FORMAT_SECTION_NUMBER",
				     "Manual section number '$1' does not match with the file extension\n" . $herecurr);
			}
# check modification date
			if ($linewds[3] !~ /^\"?[\d]{4}\-[\d]{2}\-[\d]{2}\"?$/) {
				$linewds[3] =~ /(.*)/;
				WARN("TITLE_FORMAT_DATE",
				     "'$1' incorrect date formatting, not YYYY-MM-DD\n" . $herecurr);
				next;
			}
			if ($linewds[3] =~ /\"(.*)\"/) {
				CHK("TITLE_FORMAT_DATE_QUOTED",
					"Remove the quotes from the well formatted date\n" . $herecurr);
			}
			my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
			my $currdate = strftime "%F", localtime;
			$linewds[3] =~ /(\d+)\-(\d+)\-(\d+)/;
			my $modyear = $1;
			my $modmon = $2;
			my $modday = $3;
			if ($modmon < 3) {
				$modyear--;
				$modmon += 12;
			}
			if ($modyear !~ strftime("%Y", localtime) || $modmon < $mon - 3) {
				CHK("UPDATE_MODIFICATION_DATE",
					"The modification date is currently ".$linewds[3]." it should be updated to $currdate\n" . $herecurr);
			}
# check source
			$line =~ /\"?[\d]{4}\-[\d]{2}\-[\d]{2}\"?\s((\"\S)?[^\"]*(\S\"|[^\s\"]))/;
			my $source = $1;
			if ($llapi) {
				if ($source !~ /^\"Lustre User API\"$/) {
					WARN("TITLE_FORMAT_API_SOURCE",
					     "Page source '$source' not '\"Lustre User API\"'\n" . $herecurr);
				}
			} elsif ($source !~ /^\"?Lustre\"?$/) {
				WARN("TITLE_FORMAT_SOURCE",
				     "Page source '$source' not 'Lustre'\n" . $herecurr);
			}
# check manual-section
			my $suggested_section = '';
			for ($section_number) {
			$suggested_section = 'Lustre User Utilities' if (/1/);
			$suggested_section = 'Lustre System Calls' if (/2/);
			$suggested_section = 'Lustre Library Functions' if (/3/);
			$suggested_section = 'Lustre Kernel Interfaces' if (/4/);
			$suggested_section = 'Lustre File Formats' if (/5/);
			$suggested_section = 'Lustre Games' if (/6/);
			$suggested_section = 'Lustre Miscellaneous Information' if (/7/);
			$suggested_section = 'Lustre Configuration Utilities' if (/8/);
			}
			$line =~ /$source\s(.*)$/;
			my $manual_section = $1;
			if ($manual_section && $manual_section !~ /\".+\"/) {
				ERROR("TITLE_FORMAT_SECTION_NOT_QUOTED",
				      "Manual Section not quoted '$manual_section'\n" . $herecurr);
			}
			if ($manual_section && $manual_section !~ /$suggested_section/) {
				CHK("TITLE_FORMAT_NON_STANDARD_SECTION",
				    "Non-standard manual section $manual_section, suggested to use \"$suggested_section\"\n" . $herecurr);
			}
		}

# check for lines using <> for mandatory arguments
		if ($section_number =~ /[18]/ && $line =~ /^\.[BIR].*\<.+\>/ && $line !~ /\#include/) {
			WARN("BAD_ARGUMENT_FORMAT",
			     "Avoid using '< >' to enclose mandatory arguments, if there are multiple possible mandatory arguments like A|B|C instead use '{A|B|C}' otherwise simply remove '< >'\n" . $herecurr);
		}

# check that only proper sections are used with .SH
		if ($line =~ /^\.(S[HS])\s\"?(.*)\"?/) {
			my $header = $2;
			if ($prevline =~ /^\.([TPL]?P|br|sp)/) {
				WARN("MACRO_BEFORE_HEADER",
				     "Do not use a spacing macro directly before a section or subsection header (.SH|.SS)\n" . $hereprev);
			}

			if ($line =~ /^\.(S[HS]) \".*\"/) {
				WARN("SECTION_HEADER_QUOTED",
				     "Remove the quotes the section header\n" . $herecurr);
			}
			next if ($1 =~ /SS/);

# check ending of last section
			for ($curr_header) {
			if (/SYNOPSIS/) {
				if ($section_number =~ /[18]/ && $prevline !~ /^\.YS$/) {
					ERROR("SYNOPSIS_FORMAT_MISSING_YS",
					      "The SYNOPSIS section must end with '.YS'\n" . $hereprev);
				} elsif ($section_number =~ /[23]/ && $prevline !~ /^\.fi$/) {
					ERROR("SYNOPSIS_FORMAT_MISSING_FI",
					      "The SYNOPSIS section must end with '.fi' for proper function formatting\n" . $hereprev);
				}
			}
			if (/AVAILABILITY/) {
				if (! $avail_has_release || ! $avail_has_commit) {
					my $versions = '';
					foreach my $subject (split(", ", $subjectline)) {
						$versions .= get_subject_version($subject) . "\n";
					}
					if (! $versions) {
						$versions = get_subject_version($filename) . "\n";
					}
					ERROR("AVAILABILITY_FORMAT_VERSION", <<"EOM"
Missing 'release X.X.0' and/or 'commit X.X.X*' for the SUBJECT of this man page.
If different than the SUBJECT release, options should have the release of when they were added in this section.
To find the appropriate versions, the following command will give a reasonable result:
git describe \$(git log -S 'SUBJECT' FILE | awk '/^commit /{print \$2}'|tail -1)
where SUBJECT is the user command or function that this page describes (the SUBJECT for lctl-list_param.1 would be 'list_param', include the single quotes),
and where FILE is the file path to where the function for the SUBJECT is likely found (lustre/utils/lfs.c, lustre/utils/liblustreapi*.c, ...)
Generated result:
$versions
EOM
					);
				}
				if ($avail_has_inclusion == 0) {
					my $source_type = ($llapi)? 'user application interface library' : 'filesystem package';
					WARN("AVAILABILITY_FORMAT_MISSING_IS_PART_OF",
					     "Missing line stating that the SUBJECT is part of lustre(7), typically formatted as:\n.B SUBJECT\nis part of the\n.BR lustre (7)\n$source_type\n");
				}
			}
			}

			$curr_header = find_section_header($header);
			if ($header !~ $curr_header) {
				if ($curr_header eq "") {
					WARN("BAD_SECTION_HEADER",
					     "Non-standard section: $header\n" . $herecurr);
				} else {
					WARN("BAD_SECTION_HEADER",
					     "Non-standard section: '$header' - perhaps '$curr_header'?\n" . $herecurr);
				}
			}
# check if the section is still among the remaining ones
			if ($valid_header_order && $curr_header && grep(/^$curr_header$/, @standard_headers) &&
				! grep(/^$curr_header$/, @remaining_headers)) {
				$valid_header_order = 0;
				ERROR("SECTION_HEADER_ORDER",
				      "Section header $curr_header is either out of order or duplicated.\nThe sections should be ordered as follows:\n" . join("\n", @standard_headers) . "\n" . $herecurr);
			} elsif ($valid_header_order && $curr_header) {
				my $header = shift(@remaining_headers);
				while ($header && $header !~ $curr_header) {
# check if a required section is being skipped
					if ($header !~ $curr_header) {
						my $missing_section = 0;
						for ($header) {
						$missing_section = 1 if (/NAME/);
						$missing_section = 1 if (/SYNOPSIS/ && $section_number =~ /[^45]/);
						$missing_section = 1 if (/DESCRIPTION/);
						$missing_section = 1 if (/AVAILABILITY/);
						$missing_section = 1 if (/SEE ALSO/);
						}
						ERROR("MISSING_REQUIRED_SECTION",
						      "Missing the required header $header for manual section ($section_number)\n" . $herecurr) if $missing_section;
					}
					$header = shift(@remaining_headers);
				}
			}
			next;
		} elsif ($prevline =~ /^\.S[HS]/ && $line =~ /^\.([PL]?P|br|sp)/) {
				WARN("MACRO_BEFORE_HEADER",
				     "Do not use a spacing macro directly after a section or subsection header (.SH|.SS)\n" . $hereprev);
		}

# check formatting for each section
# this is where section specific rules (if any) should be added
		for ($curr_header) {
		if (/NAME/) {
			if ($prevline !~ /NAME/) {
				ERROR("NAME_FORMAT_LINES",
				      "The name section should only be a single line\n" . $herecurr);
			} elsif ($line =~ /^((\S+,\s)*\S+)\s\\?-/) {
				$subjectline = $1;
			} else {
				if ($line !~ /\\-/) {
					ERROR("NAME_FORMAT_DASH",
					      "Missing '\\-' after names. Prefer over '-' for parsing compatibility\n" . $herecurr);
				} else {
					WARN("NAME_FORMAT_SINGLE_WORDS",
					     "The names should be single words (seperated by ', ' if there are multiple), then followed by \\- then a short description\n" . $herecurr);
				}
			}
		}
		if (/LIBRARY/) {}
		if (/SYNOPSIS/) {
			if ($prevline =~ /SYNOPSIS/) {
# check section 1 and 8 for using .SY as those are the sections that describe commands
				if ($section_number =~ /[18]/ && $line !~ /^\.SY (\".+\"|\S+)$/) {
					ERROR("SYNOPSIS_FORMAT_MISSING_SY",
					      "The SYNOPSIS section must start with '.SY \"COMMAND\"' (where COMMAND is the command described by this page) with options on following lines, if there are multiple commands, they must follow the same format\n" . $herecurr);
# check section 3 for .nf as this section describe functions
				} elsif ($section_number =~ /[23]/ && $line !~ /^\.nf$/) {
					ERROR("SYNOPSIS_FORMAT_MISSING_NF",
					      "The SYNOPSIS section must start with '.nf' for proper function formatting\n" . $herecurr);
				}
			}
		}
		if (/CONFIGURATION/) {}
		if (/DESCRIPTION/) {}
		if (/OPTIONS/) {
			if ($prevline =~ /^\.TP/) {
				if ($line =~ /[^\-]\-\w[^\w]/ && $line =~ /\-\-\w+/) {
					if ($line !~ /^\.BR (\-\w) \", \" (\-\-\w+)/) {
						WARN("OPTIONS_FORMAT_SHORT_LONG_OPT",
						     "Option header should be of the following format: .BR -SHORT_OPT \", \" --LONG_OPT [ARGS]\n" . $herecurr);
					}
				} elsif ($line =~ /[^\-]\-\w[^\w]/ && $line !~ /^\.B[IR]? (\-\w)/) {
					WARN("OPTIONS_FORMAT_SHORT_OPT_ONLY",
					     "Option header for short opt only should be of the following format: .B[IR]? -SHORT_OPT [ARGS]\n" . $herecurr);
				} elsif ($line =~ /\-\-\w+/ && $line !~ /^\.B[IR]? (\-\-\w+)/) {
					WARN("OPTIONS_FORMAT_LONG_OPT_ONLY",
					     "Option header for long opt only should be of the following format: .B[IR]? --LONG_OPT [ARGS]\n" . $herecurr);
				} elsif ($line =~ /^\.I (.+)\b/ && $1 =~ /[a-z]/) {
					CHK("OPTIONS_FORMAT",
					    "Option arguments should be italicized (.I) and ALL_CAPS, unless it is a string literal, which should be bold (.B)\n" . $herecurr);
				}
			}
		}
		if (/EXIT STATUS/) {}
		if (/RETURN VALUE/) {}
		if (/ERRORS/) {} # The error list should be in alphabetical order
		if (/ENVIRONMENT/) {}
		if (/FILES/) {}
		if (/ATTRIBUTES/) {}
		if (/VERSIONS/) {}
		if (/HISTORY/) {}
		if (/NOTES/) {}
		if (/CAVEATS/) {}
		if (/BUGS/) {}
		if (/EXAMPLES/) {
			if ($line =~ /^\.br/) {
				WARN("EXAMPLES_FORMAT_MACROS",
				     "Prefer using .EX and .EE to encase the example over using .br after each line to format examples\n" . $herecurr);
			}
			if ($line =~ /^\.TP/) {
				WARN("EXAMPLES_FORMAT_NO_TP",
				     "Prefer using .PP over .TP to format example descriptions as .TP (tagged paragraph) should only be followed by a short tag not a description, then use .RS and .RE to indent the following example\n" . $herecurr);
			}
			if ($line =~ /^\.RS (\d+)/) {
				CHK("EXAMPLES_FORMAT_INDENT",
				    "The .RS macro should not be followed by an argument in EXAMPLES so that the default indent amount is used\n" . $herecurr);
			}
			if ($line =~ /^\.(EX|RS)/) {
				my $description_line = ($prevline !~ /^\.([A-Z]+|RS \d+)$/) ? $prevline : $lines[$linenr - 3];
				if ($description_line !~ /\:\"?$/) {
					CHK("EXAMPLES_FORMAT_COLON",
					    "Example descriptions should end with ':'\n" . $hereprev);
				}
			}
			if (! $llapi) {
				if ($line =~ /^(\.[BIR][BIR]? )?[#\$]/ && $line !~ /^\.B/) {
					ERROR("EXAMPLES_FORMAT_BOLD",
					      "Lines showing user input must be bold (.B)\n" . $herecurr);
				} else {
					foreach my $subject (split(", ", $subjectline)) {
						$subject =~ s/\-/ /;
						if ($line =~ /$subject/ && $line !~ /^\.B [#\$]/) {
							CHK("EXAMPLES_FORMAT_USER_INPUT",
							    "If this line is user input, it should be bold (.B) and prefaced with either '#'/'\$' for root/non-root users respectively\n" . $herecurr);
						}
					}
				}
			}
		}
		if (/AUTHORS/) {
			if ($line =~ /((are|is).+part.+of|filesystem|distributed)/i) {
				WARN("AUTHORS_FORMAT_WRONG_INFO",
				     "It looks like this section contains information on Lustre availability, this should be place under the AVAILABILITY header\n" . $herecurr);
			}
		}
		if (/AVAILABILITY/) {
			my $line_index;
			my $tmp_line = $line;

			if ($line =~ /release \d+\.\d+\.(\d+)/) {
				$avail_has_release = 1;
				if ($1 !~ /0/) {
					CHK("AVAILABILITY_FORMAT_RELEASE",
					    "The release version usually ends with .0 as it is the first release after the commit version (commit 2.4.8 -> release 2.5.0)\n" . $herecurr);
				}
			}
			if ($line =~ /commit v?\d+.\d+.\d+/) {
				$avail_has_commit = 1;
				if ($line !~ /^\.\\\"/) {
					WARN("AVAILABILITY_FORMAT_COMMENT_COMMIT",
					     "To avoid excess information given to users, the line containing the commit version should be commented out with the following format:\n.\\\" Added in commit (X.X.X*|vX_X_X*)\n" . $herecurr);
				}
			}
			if ($line =~ /(is|are).+part.+of/) {
				$avail_has_inclusion = 1;
				my $subject_index = ($lines[$linenr - 3] =~ /subcommand.+of/)? $linenr - 4 : $linenr - 2;
				my $heretmp = "#$subject_index: FILE: $filepath:$subject_index:\n" . $lines[$subject_index];
				if ($lines[$subject_index] !~ /^\.B\b/) {
					WARN("AVAILABILITY_FORMAT_SUBJECT_BOLD",
					     "If this is the SUBJECT, it should be bold (.B) and should appear in the as it would for usage (i.e. 'lctl-lcfg_fork (8)' should be 'lctl lcfg_fork')\n" . $heretmp);
					next;
				}
				$lines[$subject_index] =~ /^\.B\b(.*)$/;
				foreach my $word (split(" ", $1)) {
					if ($filename !~ /$word/ && get_edit_distance($filename, $word) > 3) {
						CHK("AVAILABILITY_FORMAT_SUBJECT_CONTENT",
						    "Check that SUBJECT is correct, $word is not part of $filename\n" . $heretmp);
						last;
					}
				}
			} elsif ($prevline =~ /(is|are).+part.+of/) {
				if ($line !~ /^\.BR lustre \(7\)/ ||
					((! $llapi && $lines[$linenr] !~ /^filesystem package/) ||
					 ($llapi && $lines[$linenr] !~ /^user application interface library/))) {
					 my $source_type = ($llapi)? 'user application interface library' : 'filesystem package';
					CHK("AVAILABILITY_FORMAT_IS_PART_OF",
					    "The lines directly following 'is/are part of the' are expected to be:\n.BR lustre (7)\n$source_type [...]\n" . $hereprev . $lines[$linenr]);
				}
			}
			if ($line =~ /\blustre\b/i && $line !~ /^\.BR lustre \(7\)$/) {
				WARN("AVAILABILITY_FORMAT_LUSTRE_REF",
				     "Prefer referencing to Lustre with the lustre(7) man page: .BR lustre (7)\n" . $herecurr);
			}
		}
		if (/SEE ALSO/) {
			if ($line !~ /^\.BR \b.*\b \([1-8]\),?$/) {
				next if ($see_also_done_refs);
				if ($prevline =~ /^\.BR \b.*\b \([1-8]\)(,)?$/) {
					$see_also_done_refs = 1;
					if ($1) {
						$prevline =~ /(.*)$/;
						WARN("SEE_ALSO_FORMAT_COMMA",
						     "'$1' should NOT end with ',' if it is the last reference\n" . $hereprev);
					}
				} else {
					WARN("SEE_ALSO_FORMAT_STYLE",
					     "SEE ALSO lines must be of the following form: '.BR PAGE_NAME (SECTION_NUMBER)'\n" . $herecurr);
				}
				next;
			} elsif ($see_also_done_refs) {
				$see_also_done_refs = 0;
				WARN("SEE_ALSO_NON_REFERENCE",
					 "All non-reference information must be at the end of this section (all man page references must be sequential).\n" . $hereprev);
				next;
			}
			if ($prevline !~ /SEE ALSO/) {
# The list should be ordered by section number and then alphabetically by name.
				$prevline =~ /.BR \b(.*)\b \(([1-8])\)/;
				my $prevfile = $1;
				my $prevnum = $2;
				$line =~ /.BR \b(.*)\b \(([1-8])\)/;
				my $currfile = $1;
				my $currnum = $2;
				# remove non-letters for comparison
				$currfile =~ s/[\_\-]/ /g;
				$prevfile =~ s/[\_\-]/ /g;
				if (($currnum cmp $prevnum) == -1  ||
					(($currnum cmp $prevnum) == 0 && ($currfile cmp $prevfile) == -1)) {
					WARN("SEE_ALSO_FORMAT_ORDER",
					     "SEE ALSO lines must sorted by section number then alphabetically by page name, $currfile ($currnum) goes before $prevfile ($prevnum)\n" . $hereprev);
				}
# Check for a comma at the end of the line
				if ($prevline !~ /,$/) {
					$prevline =~ /(.*)$/;
					WARN("SEE_ALSO_FORMAT_COMMA",
					     "'$1' should end with ',' if it is NOT the last reference\n" . $hereprev);
				}
			}
		}
		}
	}

	print report_dump();
	if ($quiet == 0) {
		if ($clean == 1) {
			print "The man page $vname has no obvious style problems.\n";
		} else {
			print "total: $cnt_error errors, $cnt_warn warnings, " .
				(($check)? "$cnt_chk checks, " : "") .
				"$cnt_lines lines checked\n" .
				"The man page $vname has style problems.\n";
		}
	}
	return $clean
}