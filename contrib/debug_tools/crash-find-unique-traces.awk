#!/usr/bin/awk -f
# parse stack traces and identify interesting threads, avoiding the common
# threads that are just sleeping and not doing anything interesting.
#
# works with stack traces from "crash foreach bt", and kernel stacks from
# "sysrq-t" or "echo t > /proc/sysrq-trigger" with timestamps/kernel:
# stripped via "sed -e 's/.*kernel: //'"
BEGIN {
	unique_nr=0
}
function add_unique_chain(chain) {
	if (chain=="")
		return
	for (i = 0; i < unique_nr; i++) {
		if (unique[i] == chain) {
			#print "appending["i"]: "command":"current_pid
			unique_num[i]++
			unique_pids[i] = unique_pids[i] command":"current_pid" "
			return 0
		}
	}
	#print "adding["unique_nr"]: "command":"current_pid":: "chain
	unique_num[unique_nr]++
	unique_pids[unique_nr] = unique_pids[unique_nr] command":"current_pid" "
	unique[unique_nr++] = chain
}

function add_to_chain(tmp) {
	# not currently processing a stack
	if (collect_chain==0)
		return

	# skip duplicate/common parts of every stack
	if (tmp=="?")
		return
	if (index(tmp, "__cond_resched"))
		return
	if (index(tmp, "_cond_resched"))
		tmp="schedule"
	if (index(tmp, "do_syscall_64"))
		return
	if (index(tmp, "entry_SYSCALL"))
		return
	if (index(tmp, "ret_from_fork"))
		return
	if (index(tmp, "__schedule"))
		return
	if (index(tmp, "schedule_timeout"))
		return
	if (index(tmp, "schedule_hrtimeout_range"))
		return
	if (index(tmp, "system_call_fastpath"))
		return
	if (index(tmp, "SyS_select"))
		return
	if (index(tmp, "SyS_pselect"))
		return
	if (index(tmp, "sys_select"))
		return

	# strip off function offset/length
	sub("[+]0x[0-9a-f]+[/].*", "", tmp)
	if (index(tmp, "kthread"))
		return

	if (chain=="")
		chain=tmp
	else
		chain=chain","tmp
}

function dump_chain(why)
{
	if (collect_chain) {
		#printf "dumping(%s): %s\n", why, command_name
		add_unique_chain(chain)
		chain=""
		collect_chain=0
		skip_unknown=0
	}
}

/Missed [0-9]* kernel messages/ {
	if (collect_chain) {
		incomplete=1
		dump_chain("incomplete")
	}
}

# > crash -s
# PID: 0      TASK: ffffffff82013480  CPU: 0   COMMAND: "swapper/0"
#  #0 [ffffffff82003e28] __schedule at ffffffff81610f2e
#  #1 [ffffffff82003ec8] schedule_idle at ffffffff8161181e
/PID: .*TASK: / {
	dump_chain("PID")
	collect_chain=1
	for (i = 1; i < 12; i++) {
		if ($i == "PID:") {
			start_offset=i-1
			break
		}
	}
	current_pid=$(2+start_offset)
	command=$(8+start_offset)
	#print $0
	#printf "P: offset=%u, pid=%u, command=%s\n",
	#	start_offset, current_pid, command
}

#  #2 [ffffffff82003ed0] do_idle at ffffffff810cddaf
#  #3 [ffffffff82003ef0] cpu_startup_entry at ffffffff810cdfef
/#[0-9]* / {
	add_to_chain($(3+start_offset))
}


# SysRq : Show State
#   task                        PC stack   pid father
# mdt04_084       R  running task        0 141145      2 0x00000080
# Call Trace:
#  [<ffffffffbc0d66a6>] __cond_resched+0x26/0x30
#  [<ffffffffbc77f4ca>] _cond_resched+0x3a/0x50
#  [<ffffffffbc223495>] kmem_cache_alloc+0x35/0x1f0
#  [<ffffffffc0dc363c>] LNetMDBind+0x7c/0x5e0 [lnet]
/ R  running task / {
	dump_chain("running")
	collect_chain=1
	#skip_unknown=1
	for (i = 1; i < 12; i++) {
		if ($i == "R") {
			start_offset=i-2
			break
		}
	}
	current_pid=$(6+start_offset)
	command=$(1+start_offset)
	#print $0
	#printf "%s: offset=%u, pid=%u, command=%s\n", $(2+start_offset),
	#	start_offset, current_pid, command
}

# SysRq : Show State
#   task                        PC stack   pid father
# bash            S ffff8e3295fdb150     0 227559 227404 0x00000080
# worker          D ffff8abbbfb1ac80     0  4090      1 0x00000000
# Call Trace:
#  [<ffffffffbc77f229>] schedule+0x29/0x70
#  [<ffffffffbc0a07a6>] do_wait+0x1f6/0x260
# this regexp is x86_64-specific
/ [SD] ffff[0-9a-f]* / {
	dump_chain("sleeping")
	collect_chain=1
	for (i = 1; i < 12; i++) {
		if ($i == "S" || $i == "D") {
			start_offset=i-2
			break
		}
	}
	current_pid=$(5+start_offset)
	command=$(1+start_offset)
	#print $0
	#printf "%s: offset=%u, pid=%s, command=%s\n", $(2+start_offset),
	#	start_offset, current_pid, command
}

# mdt01_001: page allocation failure: order:4, mode:0x10c050
# CPU: 1 PID: 9374 Comm: mdt01_001 Kdump: loaded Tainted: G
# Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS VirtualBox 12/01/2006
# Call Trace:
#  [<ffffffffbc563021>] dump_stack+0x19/0x1b
#  [<ffffffffbbfbcbf0>] warn_alloc_failed+0x110/0x180
/CPU: [0-9]* PID: [0-9]* Comm: / {
	dump_chain("dump")
	collect_chain=1
	for (i = 1; i < 8; i++) {
		if ($i == "CPU:")
			start_offset=i-1
	}
	current_pid=$(4+start_offset)
	command=$(6+start_offset)
}

#  [<ffffffffbc296ba9>] ? ep_scan_ready_list.isra.7+0x1b9/0x1f0
#  [<ffffffffbc77e363>] schedule_hrtimeout_range+0x13/0x20
# this regexp is x86_64-specific
/ \[<ffff[0-9a-f]*>\] / {
	this_offset=2
	if (skip_unknown==1) {
		if ($(start_offset+this_offset)=="?")
			this_offset++
		#print "adding @"this_offset": "$(start_offset+this_offset)
	}
	add_to_chain($(start_offset+this_offset))
}

/ret_from_fork/ {
	dump_chain("ret")
}

/entry_SYSCALL/ {
	dump_chain("syscall")
}

END {
	if (incomplete)
		print "**** messages lost, stack traces may be incomplete ****"
	i=0
	# this list should be kept sorted to avoid duplicates
	# "!}sort" on next line in Vim
	not_interesting[i++]="default_idle,do_idle,cpu_startup_entry,secondary_startup_64"
	not_interesting[i++]="default_idle,do_idle,cpu_startup_entry,start_kernel,secondary_startup_64"
	not_interesting[i++]="sched_show_task,show_state_filter,sysrq_handle_showstate,__handle_sysrq,write_sysrq_trigger,proc_reg_write,vfs_write,SyS_write"
	not_interesting[i++]="schedule"
	not_interesting[i++]="schedule,__se_sys_rt_sigtimedwait"
	not_interesting[i++]="schedule,cfs_wi_scheduler"
	not_interesting[i++]="schedule,devtmpfsd"
	not_interesting[i++]="schedule,distribute_txn_commit_thread"
	not_interesting[i++]="schedule,do_nanosleep,hrtimer_nanosleep,SyS_nanosleep"
	not_interesting[i++]="schedule,do_select"
	not_interesting[i++]="schedule,do_select,kern_select"
	not_interesting[i++]="schedule,do_sys_poll,SyS_poll"
	not_interesting[i++]="schedule,do_sys_poll,SyS_ppoll"
	not_interesting[i++]="schedule,do_sys_poll,__se_sys_poll"
	not_interesting[i++]="schedule,do_wait,SyS_wait4"
	not_interesting[i++]="schedule,do_wait,kernel_wait4,__se_sys_wait4"
	not_interesting[i++]="schedule,ep_poll,SyS_epoll_wait"
	not_interesting[i++]="schedule,ep_poll,SyS_epoll_wait,SyS_epoll_pwait"
	not_interesting[i++]="schedule,ep_poll,do_epoll_wait,__x64_sys_epoll_wait"
	not_interesting[i++]="schedule,expired_lock_main"
	not_interesting[i++]="schedule,futex_wait_queue_me,futex_wait,do_futex,SyS_futex"
	not_interesting[i++]="schedule,ib_fmr_cleanup_thread"
	not_interesting[i++]="schedule,ipmi_thread"
	not_interesting[i++]="schedule,kauditd_thread"
	not_interesting[i++]="schedule,kcompactd"
	not_interesting[i++]="schedule,khugepaged"
	not_interesting[i++]="schedule,khvcd"
	not_interesting[i++]="schedule,kiblnd_connd"
	not_interesting[i++]="schedule,kiblnd_scheduler"
	not_interesting[i++]="schedule,kjournald2"
	not_interesting[i++]="schedule,ksm_scan_thread"
	not_interesting[i++]="schedule,ksocknal_connd"
	not_interesting[i++]="schedule,ksocknal_reaper"
	not_interesting[i++]="schedule,ksocknal_scheduler"
	not_interesting[i++]="schedule,kswapd"
	not_interesting[i++]="schedule,kthread_worker_fn"
	not_interesting[i++]="schedule,kthreadd"
	not_interesting[i++]="schedule,lcw_dispatch_main"
	not_interesting[i++]="schedule,ldlm_bl_thread_main"
	not_interesting[i++]="schedule,ll_agl_thread"
	not_interesting[i++]="schedule,ll_statahead_thread"
	not_interesting[i++]="schedule,lnet_acceptor"
	not_interesting[i++]="schedule,lnet_monitor_thread"
	not_interesting[i++]="schedule,lnet_peer_discovery"
	not_interesting[i++]="schedule,lnet_sock_accept,lnet_acceptor"
	not_interesting[i++]="schedule,mdt_coordinator"
	not_interesting[i++]="schedule,mgc_requeue_thread"
	not_interesting[i++]="schedule,mgs_ir_notify"
	not_interesting[i++]="schedule,n_tty_read,tty_read,vfs_read,SyS_read"
	not_interesting[i++]="schedule,ofd_inconsistency_verification_main"
	not_interesting[i++]="schedule,oom_reaper"
	not_interesting[i++]="schedule,osp_precreate_thread"
	not_interesting[i++]="schedule,osp_send_update_thread"
	not_interesting[i++]="schedule,osp_sync_process_queues,llog_process_thread,llog_process_or_fork,llog_cat_process_cb,llog_process_thread,llog_process_or_fork,llog_cat_process_or_fork,llog_cat_process,osp_sync_thread"
	not_interesting[i++]="schedule,ping_evictor_main"
	not_interesting[i++]="schedule,pipe_wait,pipe_read,__vfs_read,vfs_read,ksys_read"
	not_interesting[i++]="schedule,poll_do_select"
	not_interesting[i++]="schedule,ptlrpc_hr_main"
	not_interesting[i++]="schedule,ptlrpc_wait_event,ptlrpc_main"
	not_interesting[i++]="schedule,ptlrpcd"
	not_interesting[i++]="schedule,qmt_reba_thread"
	not_interesting[i++]="schedule,qsd_upd_thread"
	not_interesting[i++]="schedule,rcu_gp_kthread"
	not_interesting[i++]="schedule,rescuer_thread"
	not_interesting[i++]="schedule,sched_show_task,show_state_filter,sysrq_handle_showstate,__handle_sysrq,write_sysrq_trigger,proc_reg_write,vfs_write,SyS_write"
	not_interesting[i++]="schedule,scsi_error_handler"
	not_interesting[i++]="schedule,smpboot_thread_fn"
	not_interesting[i++]="schedule,sys_pause"
	not_interesting[i++]="schedule,wait_for_common,lnet_monitor_thread"
	not_interesting[i++]="schedule,watchdog"
	not_interesting[i++]="schedule,worker_thread"

	for (i = 0; i < unique_nr; i++) {
		dump=1
		for (j in not_interesting) {
#			if (index(unique[i], not_interesting[j])) {
#				dump=0
#				break
#			}
			if (unique[i]==not_interesting[j]) {
				dump=0
				break
			}
		}
		if (dump)
			printf("%s\n\tPIDs(%d): %s\n\n",
			       unique[i],unique_num[i],unique_pids[i])
	}

}

