/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Tracepoints exported from libcfs_debug_msg() so that eBPF, perf and
 * ftrace tools can capture Lustre debug messages at runtime.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM lustre_debug

#if !defined(__LUSTRE_DEBUG_EVENTS_H) || defined(TRACE_HEADER_MULTI_READ)
#define __LUSTRE_DEBUG_EVENTS_H

#include <linux/tracepoint.h>
#include <linux/libcfs/libcfs_debug.h>

#ifndef __LUSTRE_DEBUG_EVENTS_HELPERS
#define __LUSTRE_DEBUG_EVENTS_HELPERS

/*
 * perf and BPF consumers drop records over PERF_MAX_TRACE_SIZE, which is
 * 2048 before v6.6, so keep the three caps plus the event header below it.
 */
#define LUSTRE_DEBUG_FILE_MAX	256
#define LUSTRE_DEBUG_FN_MAX	128
#define LUSTRE_DEBUG_MSG_MAX	1536

/* bytes needed to store @s, including the NUL, capped at @max */
static inline int lustre_debug_strlen(const char *s, int max)
{
	return strnlen(s ?: "", max - 1) + 1;
}

static inline void lustre_debug_strcpy(char *dst, const char *s, int max)
{
	int len = lustre_debug_strlen(s, max) - 1;

	memcpy(dst, s ?: "", len);
	dst[len] = '\0';
}

/* bytes needed to format @vaf, including the NUL, capped at @max */
static inline int lustre_debug_vlen(struct va_format *vaf, int max)
{
	va_list args;
	int len;

	va_copy(args, *vaf->va);
	len = vsnprintf(NULL, 0, vaf->fmt, args);
	va_end(args);

	return min(len + 1, max);
}

#endif /* __LUSTRE_DEBUG_EVENTS_HELPERS */

/*
 * lustre_debug_msg: location, subsystem, mask and formatted text of
 * every debug message, whether or not it reaches the debug buffer.
 */
TRACE_EVENT(lustre_debug_msg,
	TP_PROTO(const struct libcfs_debug_msg_data *msgdata,
		 struct va_format *vaf),
	TP_ARGS(msgdata, vaf),
	TP_STRUCT__entry(
		__dynamic_array(char, msg_file,
			lustre_debug_strlen(kbasename(msgdata->msg_file),
					    LUSTRE_DEBUG_FILE_MAX))
		__dynamic_array(char, msg_fn,
				lustre_debug_strlen(msgdata->msg_fn,
						    LUSTRE_DEBUG_FN_MAX))
		__field(int, msg_subsys)
		__field(int, msg_line)
		__field(int, msg_mask)
		__dynamic_array(char, msg,
				lustre_debug_vlen(vaf, LUSTRE_DEBUG_MSG_MAX))
	),
	TP_fast_assign(
		char *buf = __get_str(msg);
		va_list args;
		int len;

		lustre_debug_strcpy(__get_str(msg_file),
				    kbasename(msgdata->msg_file),
				    __get_dynamic_array_len(msg_file));
		lustre_debug_strcpy(__get_str(msg_fn), msgdata->msg_fn,
				    __get_dynamic_array_len(msg_fn));
		__entry->msg_subsys = msgdata->msg_subsys;
		__entry->msg_line = msgdata->msg_line;
		__entry->msg_mask = msgdata->msg_mask;
		/* each attached consumer runs this, so leave vaf->va intact */
		va_copy(args, *vaf->va);
		len = vscnprintf(buf, __get_dynamic_array_len(msg), vaf->fmt,
				 args);
		va_end(args);
		while (len > 0 && buf[len - 1] == '\n')
			buf[--len] = '\0';
	),
	TP_printk("subsys=0x%x mask=0x%x %s:%d %s() %s",
		  __entry->msg_subsys,
		  __entry->msg_mask,
		  __get_str(msg_file),
		  __entry->msg_line,
		  __get_str(msg_fn),
		  __get_str(msg))
);

/*
 * lustre_debug_location: location, subsystem and mask of a debug
 * message, without the cost of formatting its text.
 */
TRACE_EVENT(lustre_debug_location,
	TP_PROTO(const struct libcfs_debug_msg_data *msgdata),
	TP_ARGS(msgdata),
	TP_STRUCT__entry(
		__dynamic_array(char, msg_file,
			lustre_debug_strlen(kbasename(msgdata->msg_file),
					    LUSTRE_DEBUG_FILE_MAX))
		__dynamic_array(char, msg_fn,
				lustre_debug_strlen(msgdata->msg_fn,
						    LUSTRE_DEBUG_FN_MAX))
		__field(int, msg_subsys)
		__field(int, msg_line)
		__field(int, msg_mask)
	),
	TP_fast_assign(
		lustre_debug_strcpy(__get_str(msg_file),
				    kbasename(msgdata->msg_file),
				    __get_dynamic_array_len(msg_file));
		lustre_debug_strcpy(__get_str(msg_fn), msgdata->msg_fn,
				    __get_dynamic_array_len(msg_fn));
		__entry->msg_subsys = msgdata->msg_subsys;
		__entry->msg_line = msgdata->msg_line;
		__entry->msg_mask = msgdata->msg_mask;
	),
	TP_printk("subsys=0x%x mask=0x%x %s:%d %s()",
		  __entry->msg_subsys,
		  __entry->msg_mask,
		  __get_str(msg_file),
		  __entry->msg_line,
		  __get_str(msg_fn))
);

#endif /* __LUSTRE_DEBUG_EVENTS_H */

#include <trace/define_trace.h>
