#ifndef __PORTALS_TRACEFILE_H
#define __PORTALS_TRACEFILE_H

int tracefile_dump_all_pages(char *filename);
void trace_debug_print(void);
void trace_flush_pages(void);
int trace_start_thread(void);
void trace_stop_thread(void);
int tracefile_init(void);
void tracefile_exit(void);
int trace_write_daemon_file(struct file *file, const char *buffer,
			    unsigned long count, void *data);
int trace_read_daemon_file(char *page, char **start, off_t off, int count,
			   int *eof, void *data);
int trace_write_debug_size(struct file *file, const char *buffer,
                           unsigned long count, void *data);
int trace_read_debug_size(char *page, char **start, off_t off, int count,
                          int *eof, void *data);
int trace_dk(struct file *file, const char *buffer, unsigned long count,
             void *data);

#endif /* __PORTALS_TRACEFILE_H */
