#!/usr/bin/perl
$pristine=1;
if($ARGV[0]){chdir($ARGV[0]);}
get_linuxdir();
get_tag();
get_latest_mtime();
generate_ver();

sub get_tag
{
	$tag=open(TAG,"CVS/Tag");
	if(!$tag){
		$tag="HEAD";
	} else {
		$tag=<TAG>;
		$tag=~/.(.*)$/;
		$tag=$1;
		close(TAG);
	}
}
sub get_latest_mtime
{
	use Time::Local;
	%months=("Jan"=>1,"Feb"=>2,"Mar"=>3,"Apr"=>4,"May"=>5,
		"Jun"=>6,"Jul"=>7,"Aug"=>8,"Sep"=>9,"Oct"=>10,
		"Nov"=>11,"Dec"=>12);

	$last_mtime=0;
	@entries=`find . -name Entries`;
	foreach $entry(@entries){
		open(ENTRY,$entry);
		while(<ENTRY>)	{
			$line=$_;
			@temp_file_entry=split("/",$line);
			$time_entry=$temp_file_entry[3];
			$file=$temp_file_entry[1];
			
			$cur_dir=$entry;
			$cur_dir=~s/\/CVS\/Entries$//g;
			chomp($cur_dir);
			($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
		                    $atime,$mtime,$ctime,$blksize,$blocks)
                	= stat($cur_dir."/".$file);
			$local_date=gmtime($mtime);
			if(! ($local_date =~ /$time_entry/) && 
				!($temp_file_entry[0] =~ /D/) && 
				!($file =~ /lustre\.spec\.in/))	{ 
  				#print "$file\n";
				$pristine=0;
			}
				
			if($time_entry && 
				$file =~ m/\.c$|\.h$|\.am$|\.in$/ && 
				!($file =~ /lustre\.spec\.in/)){
	
				@time=split(" ",$time_entry);
				($hours,$min,$sec)=split(":",$time[3]);
				($mday, $mon, $year)=($time[2],$time[1],
								$time[4]);
				$secs=0;
				$mon=$months{$mon};
				if($mon>0 && $mon<13){
					$secs=timelocal($sec,$min,$hours,$mday,
							$mon,$year);
				}
				if($secs>$last_mtime){
					$last_mtime=$secs;
					$show_last=$hours.$min.$sec.
						$year.$mon.$mday;
				}

			}
		}
		close(ENTRY);
	}
}

sub get_linuxdir
{
	open(CONFIG,"config.status") or die "Run ./configure first \n";
	while($line=<CONFIG>){
		$line =~ /(.*)\%\@LINUX\@\%(.*)\%g/;
		if($2){$linuxdir=$2;last;}
	}
	close(CONFIG);
	open(VER,"$linuxdir/include/linux/version.h") 
		or die "Run make dep on $linuxdir \n";
	while($line=<VER>){
		$line =~ /#define UTS_RELEASE "(.*)"/;
		if($1){ $kernver=$1; last;}
	}
	chomp($kernver);
	$linuxdir=~s/\//\./g;
	close(VER);	
}

sub generate_ver
{
	print "#define BUILD_VERSION \"";	
	if($pristine){
		print "$tag-$show_last-PRISTINE-$linuxdir-$kernver\"\n";
	}else{
		print "$tag-$show_last-CHANGED-$linuxdir-$kernver\"\n";
	}
}
