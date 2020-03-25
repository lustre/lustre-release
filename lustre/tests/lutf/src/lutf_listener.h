#ifndef LUTF_LISTENER_H
#define LUTF_LISTENER_H

#include "lutf_common.h"

/*
 * lutf_listener_main
 *   Main loop of the listener thread
 */
void *lutf_listener_main(void *usr_data);

void lutf_listener_shutdown(void);

#endif /* LUTF_LISTENER_H */
