#!/bin/sh

#	System Profiling Script

TESTS="oprofile iostat vmstat proc_dump"

# common parameters
export OUTPUTDIR=/home/op
export KERNELDIR=/usr/src/linux
export LUSTREDIR=/usr/src/lustre
export PORTALSDIR=/usr/src/portals
NAL=socknal

# Params for OPROFILE
#CTR0_EVENT=CPU_CLK_UNHALTED
CTR0_COUNT=10000

# for intel Petium 4 onwards... Also requires Unit Mask
CTR0_EVENT=GLOBAL_POWER_EVENTS  
CTR0_UNIT_MASK=0x01

# Params for VMSTAT
VM_SAMPLING=1 

# Params for IOSTAT
IO_SAMPLING=1  

# Params for PROC DUMP
export PROC_SAMPLING=2

#-------------------------------------------------------------------
oprofile_start() {
	
	echo `date +%T`": oprofile started...." >>  $OUTPUTDIR/$HOSTNAME/summary
	op_start --ctr0-event=$CTR0_EVENT --ctr0-count=$CTR0_COUNT --ctr0-unit-mask=$CTR0_UNIT_MASK --vmlinux=${KERNELDIR}/vmlinux 
	mkdir -p ${OUTPUTDIR}/${HOSTNAME}/oprofile/prof_source/{obdclass,obdecho,osc,ptlrpc,extN,obdfilter,ost,mdc,mds4mds,mds4mds_extN,llite,portals,$NAL}
	mkdir -p ${OUTPUTDIR}/${HOSTNAME}/oprofile/profiling

}

iostat_start() {
	echo `date +%T`": iostat started...." >>  $OUTPUTDIR/$HOSTNAME/summary

	mkdir ${OUTPUTDIR}/${HOSTNAME}/iostat

	iostat $IO_SAMPLING > $OUTPUTDIR/$HOSTNAME/iostat/iostat.op &
        PID=$!
        echo $PID > $OUTPUTDIR/$HOSTNAME/tmp/iostat.pid
}

vmstat_start() {

	echo $OUTPUTDIR;
	echo `date +%T`": vmstat started...." >>  $OUTPUTDIR/$HOSTNAME/summary
	
	mkdir ${OUTPUTDIR}/${HOSTNAME}/vmstat

	vmstat $VM_SAMPLING > $OUTPUTDIR/$HOSTNAME/vmstat/vmstat.op &
        PID=$!
        echo $PID > $OUTPUTDIR/$HOSTNAME/tmp/vmstat.pid
}

proc_dump_start() {
	echo `date +%T`": proc dump started...." >> $OUTPUTDIR/$HOSTNAME/summary
	sh -c '
		CTRFILE=/$OUTPUTDIR/$HOSTNAME/tmp/running.$$.pid;
                echo $$ > ${CTRFILE};
                while [ -f $CTRFILE ]; do
			cat /proc/meminfo >> $OUTPUTDIR/$HOSTNAME/meminfo;
			cat /proc/interrupts >> $OUTPUTDIR/$HOSTNAME/interrupts;
			cat /proc/net/dev >> $OUTPUTDIR/$HOSTNAME/net-dev;
                        sleep ${PROC_SAMPLING};
                done;
                ' &
	CTRFILE=/tmp/running.$!.pid
	echo "proc_dump_ctrl $CTRFILE" >> /tmp/prof-ctrl

}

oprofile_stop() {
	op_dump
	op_stop 

	echo `date +%T`": oprofile stopped...." >>  $OUTPUTDIR/$HOSTNAME/summary

	for i in obdclass obdecho osc ptlrpc extN obdfilter mds ost mdc llite
	do
		oprofpp -l ${LUSTREDIR}/${i}/${i}.o >  ${OUTPUTDIR}/${HOSTNAME}/oprofile/profiling/${i}.prof 2>/dev/null
	done
	oprofpp -l ${LUSTREDIR}/mds/mds_extN.o > ${OUTPUTDIR}/${HOSTNAME}/oprofile/profiling/mds_extN.prof 2>/dev/null
	oprofpp -l ${PORTALSDIR}/linux/oslib/portals.o > ${OUTPUTDIR}/${HOSTNAME}/oprofile/profiling/portals.prof 2>/dev/null
	oprofpp -l ${PORTALSDIR}/linux/${NAL}/k${NAL}.o > ${OUTPUTDIR}/${HOSTNAME}/oprofile/profiling/k${NAL}.prof 2>/dev/null

			
	for i in obdclass obdecho osc ptlrpc extN obdfilter ost mdc llite
	do
		op_to_source --source-dir=${LUSTREDIR}/${i}/ --output-dir=${OUTPUTDIR}/${HOSTNAME}/oprofile/prof_source/${i}/ ${LUSTREDIR}/${i}/${i}.o 2>/dev/null
	done

	op_to_source --source-dir=${LUSTREDIR}/mds/ --output-dir=${OUTPUTDIR}/${HOSTNAME}/oprofile/prof_source/mds4mds/ ${LUSTREDIR}/mds/mds.o 2>/dev/null
	op_to_source --source-dir=${LUSTREDIR}/mds/ --output-dir=${OUTPUTDIR}/${HOSTNAME}/oprofile/prof_source/mds4mds_extN/  ${LUSTREDIR}/mds/mds_extN.o 2>/dev/null
		
	op_to_source --source-dir=${PORTALSDIR}/linux/oslib/ --output-dir=${OUTPUTDIR}/${HOSTNAME}/oprofile/prof_source/portals ${PORTALSDIR}/linux/oslib/portals.o 2>/dev/null
	op_to_source --source-dir=${PORTALSDIR}/linux/${NAL}/ --output-dir=${OUTPUTDIR}/${HOSTNAME}/oprofile/prof_source/${NAL} ${PORTALSDIR}/linux/${NAL}/k${NAL}.o 2>/dev/null

	op_time -l > ${OUTPUTDIR}/${HOSTNAME}/oprofile/globalprofile 2>/dev/null

}

iostat_stop() {
	echo `date +%T`": iostat stopped...." >>  $OUTPUTDIR/$HOSTNAME/summary
	
	PID=$(cat $OUTPUTDIR/$HOSTNAME/tmp/iostat.pid)
        kill $PID
}

vmstat_stop() { 
	echo `date +%T`": vmstat stopped...." >>  $OUTPUTDIR/$HOSTNAME/summary
	
	PID=$(cat $OUTPUTDIR/$HOSTNAME/tmp/vmstat.pid)
        kill $PID
}

oprofile_dump() {
	op_dump;
}

proc_dump_stop() {
	echo `date +%T`": proc dump stopped...." >> $OUTPUTDIR/$HOSTNAME/summary
	CTRFILE=`cat /tmp/prof-ctrl | awk '$1 == "prof_dump_ctrl" {print $2}'`
	rm -f $CTRFILE
}
#-------------------------------------------------------------------

case "$1" in 

	start)

		shift; 
		while [ ${#*} -gt 1 ]; do 
		      	case "$1" in
                        	-k)
                               		shift;
					KERNELDIR=$1;
					;;

                        	-l)
                             	   	shift;
                               		LUSTREDIR=$1;
                                	;;
                        	-p)
                             	   	shift;
                               		PORTALSDIR=$1;
                                	;;

                        	-o)
                             	   	shift;
                               		OUTPUTDIR=$1;
                                	;;
	                         *)
        		                echo unrecognized option $1
                        	        break;
                                	;;
                	esac
                	shift;
        	done
		echo "kerneldir $KERNELDIR" > /tmp/prof-ctrl
		echo -e "\nlustredir $LUSTREDIR" >> /tmp/prof-ctrl
		echo -e "\nportalsdir $PORTALSDIR" >> /tmp/prof-ctrl
		echo -e "\noutputdir $OUTPUTDIR" >> /tmp/prof-ctrl

		if [ -d ${OUTPUTDIR}/${HOSTNAME} ]; then
			echo "Output already exists"
			echo "Please take backup and remove it"
			exit 1
		fi

		mkdir -p ${OUTPUTDIR}/${HOSTNAME}
		echo -e "Profiling started on $HOSTNAME" >  ${OUTPUTDIR}/${HOSTNAME}/summary
		echo -e "\n\nModules Listing on $HOSTNAME" >> ${OUTPUTDIR}/${HOSTNAME}/summary 
		/sbin/lsmod >> ${OUTPUTDIR}/${HOSTNAME}/summary
		echo -e "\n\nKernel : " >> ${OUTPUTDIR}/${HOSTNAME}/summary
		uname -a  >> ${OUTPUTDIR}/${HOSTNAME}/summary
		echo -e "\n\nPCI Devices : "  >> ${OUTPUTDIR}/${HOSTNAME}/summary
		lspci -t -v  >> ${OUTPUTDIR}/${HOSTNAME}/summary
		echo -e "\n\nTests carried out " >> ${OUTPUTDIR}/${HOSTNAME}/summary
 	
		mkdir $OUTPUTDIR/$HOSTNAME/tmp
		for test in $TESTS; do
			${test}_start;
		done
	;;
	stop)
		
		KERNELDIR=`cat /tmp/prof-ctrl | awk '$1 == "kerneldir" {print $2}'`
		LUSTREDIR=`cat /tmp/prof-ctrl | awk '$1 == "lustredir" {print $2}'`
		PORTALSDIR=`cat /tmp/prof-ctrl | awk '$1 == "portalsdir" {print $2}'`
		OUTPUTDIR=`cat /tmp/prof-ctrl | awk '$1 == "outputdir" {print $2}'`
		for test in $TESTS; do
			${test}_stop;
		done
		
		rm -rf ${OUTPUTDIR}/$HOSTNAME/tmp	
		tar -cf ${OUTPUTDIR}/${HOSTNAME}.tar  ${OUTPUTDIR}/${HOSTNAME}
		echo "Dumped results in ${OUTPUTDIR}/${HOSTNAME}.tar"
	;;	
	dump)
		if "oprofile" in $TESTS; then
			oprofile_dump;
		fi
	;;
	clean)	

		OUTPUTDIR=`cat /tmp/prof-ctrl | awk '$1 == "outputdir" {print $2}'`
		echo Deleting directory $OUTPUTDIR/$HOSTNAME ...
		rm -rf $OUTPUTDIR/$HOSTNAME
		echo Deleting file $OUTPUTDIR/${HOSTNAME}.tar ...
		rm -rf $OUTPUTDIR/${HOSTNAME}.tar
		echo Deleting oprofile samples ...
		rm -f /var/lib/oprofile/samples/*
		rm -f /tmp/prof-ctrl
	;;
	*)
		echo $"Usage : $0 {start|stop|dump|clean} [OPTIONS]";
		echo $"OPTIONS :"
		echo $" -l lustre_dir"	
		echo $" -p portals_dir"	
		echo $" -k kernel_dir"	
		echo $" -o output_dir"	
		exit 1
esac

exit 0
