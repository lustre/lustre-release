#!/usr/bin/awk -f

function add_unique_chain(chain) {
	for (i = 0; i < unique_nr; i++) {
		if (unique[i] == chain) {
			return 0
		}
	}
	unique_pids[unique_nr] = unique_pids[unique_nr] current_pid " "
	unique[unique_nr++] = chain
}

function dump_chain()
{
	if (collect_chain) {
		#print pl_cmdname,pl_pid
		add_unique_chain(chain)
		chain=""
		collect_chain=0
	}
}

/^PID:/ {
	traces++
	dump_chain()
	collect_chain=1
	current_pid=$2
}

/#[0-9]* / {
	tmp=$3
	#if (start_to_analyze==0)
	#	next
	if (collect_chain==0)
		next
	if (index(tmp, "do_syscall_64"))
		next
	if (index(tmp, "ret_from_fork"))
		next
	if (index(tmp, "entry_SYSCALL"))
		next
	#sub("[+]0x[0-9a-f]+[/].*", "", tmp)
	if (chain=="")
		chain=tmp
	else
		chain=chain","tmp
}

/ret_from_fork/ {
	dump_chain()
}

/entry_SYSCALL/ {
	dump_chain()
}

END {
	not_interesting[0]="schedule,ldlm_bl_thread_main,kthread"
	not_interesting[1]="schedule,ptlrpcd,kthread"
	not_interesting[2]="schedule,mgc_requeue_thread,kthread"
	not_interesting[3]="schedule,schedule_timeout,ksocknal_connd,kthread"
	not_interesting[4]="schedule,ptlrpc_hr_main,kthread"
	not_interesting[5]="schedule,ksocknal_scheduler"
	not_interesting[6]="schedule,osp_precreate_thread"
	not_interesting[7]="schedule,mgs_ir_notify,kthread"
	not_interesting[8]="schedule,qmt_reba_thread,kthread"
	not_interesting[9]="schedule,expired_lock_main,kthread"
	not_interesting[10]="schedule,schedule_timeout,lnet_peer_discovery,kthread"
	not_interesting[11]="schedule,ping_evictor_main,kthread"
	not_interesting[12]="schedule,schedule_timeout,qsd_upd_thread,kthread"
	not_interesting[13]="schedule,ptlrpc_wait_event,ptlrpc_main,kthread"
	not_interesting[14]="schedule,lnet_sock_accept,lnet_acceptor,kthread"
	not_interesting[15]="schedule,schedule_timeout,lnet_monitor_thread,kthread"
	not_interesting[16]="schedule,ofd_inconsistency_verification_main,kthread"
	not_interesting[17]="schedule,schedule_timeout,ksocknal_reaper,kthread"
	not_interesting[18]="schedule,kjournald2,kthread"
	not_interesting[19]="schedule,rescuer_thread,kthread"
	not_interesting[20]="schedule,oom_reaper,kthread"
	not_interesting[21]="schedule,worker_thread,kthread"
	not_interesting[22]="schedule,kthread_worker_fn,kthread"
	not_interesting[23]="schedule,osp_sync_process_queues,llog_process_thread,llog_process_or_fork,llog_cat_process_cb,llog_process_thread,llog_process_or_fork,llog_cat_process_or_fork,llog_cat_process,osp_sync_thread,kthread"
	not_interesting[24]="schedule,smpboot_thread_fn,kthread"
	not_interesting[25]="schedule,schedule_timeout,rcu_gp_kthread,kthread"
	not_interesting[26]="schedule,rcu_gp_kthread,kthread"
	not_interesting[27]="schedule,devtmpfsd,kthread"
	not_interesting[28]="schedule,schedule_timeout,watchdog,kthread"
	not_interesting[29]="schedule,oom_reaper"
	not_interesting[30]="schedule,kcompactd,kthread"
	not_interesting[31]="schedule,schedule_timeout,khugepaged,kthread"
	not_interesting[32]="schedule,kswapd,kthread"
	not_interesting[33]="schedule,schedule_hrtimeout_range_clock,do_sys_poll,__se_sys_poll"
	not_interesting[34]="schedule,schedule_hrtimeout_range_clock,do_select,core_sys_select,kern_select,__x64_sys_select"
	not_interesting[35]="schedule,schedule_hrtimeout_range_clock,__se_sys_rt_sigtimedwait"
	not_interesting[36]="schedule,do_wait,kernel_wait4,__se_sys_wait4"
	not_interesting[37]="schedule,schedule_timeout,wait_for_common,lnet_monitor_thread,kthread"
	not_interesting[38]="schedule,schedule_hrtimeout_range_clock,ep_poll,do_epoll_wait,__x64_sys_epoll_wait"
	not_interesting[39]="schedule,kthreadd"
	not_interesting[40]="schedule,khvcd,kthread"
	not_interesting[41]="schedule,schedule_timeout,ptlrpcd,kthread"
	not_interesting[42]="schedule,schedule_timeout,mdt_coordinator,kthread"
	not_interesting[43]="schedule,distribute_txn_commit_thread,kthread"
	not_interesting[44]="schedule,lnet_acceptor,kthread"
	not_interesting[45]="schedule,osp_send_update_thread,kthread"
	not_interesting[46]="schedule,pipe_wait,pipe_read,__vfs_read,vfs_read,ksys_read"
	not_interesting[47]="default_idle,do_idle,cpu_startup_entry,start_kernel,secondary_startup_64"
	not_interesting[48]="default_idle,do_idle,cpu_startup_entry,secondary_startup_64"
	not_interesting[49]="do_select,core_sys_select,kern_select,__x64_sys_select"

#not_interesting[]=""
#not_interesting[]=""
#schedule,kthreadd

	for (i = 0; i < unique_nr; i++) {
		dump=1
		for (j in not_interesting) {
			if (index(unique[i], not_interesting[j])) {
				dump=0
				break
			}
			if (unique[i]==not_interesting[j]) {
				dump=0
				break
			}
		}
		if (dump)
			print unique[i],"PIDs:",unique_pids[i]
	}

}

