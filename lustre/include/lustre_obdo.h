/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 *
 * Copyright 2015 Cray Inc, all rights reserved.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Define obdo associated functions
 *   obdo:  OBject Device o...
 *
 * Author: Ben Evans.
 */

#ifndef _LUSTRE_OBDO_H_
#define _LUSTRE_OBDO_H_

#include <uapi/linux/lustre/lustre_idl.h>

/**
 * Create an obdo to send over the wire
 */
void lustre_set_wire_obdo(const struct obd_connect_data *ocd,
			  struct obdo *wobdo,
			  const struct obdo *lobdo);

/**
 * Create a local obdo from a wire based odbo
 */
void lustre_get_wire_obdo(const struct obd_connect_data *ocd,
			  struct obdo *lobdo,
			  const struct obdo *wobdo);
#endif
