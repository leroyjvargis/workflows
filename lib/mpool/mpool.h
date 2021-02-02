/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
/*
 * Storage manager interface for HSE
 */

#ifndef MPOOL_H
#define MPOOL_H

#include <mpool/mpool2.h>

#include "mclass.h"

struct media_class;
struct mdc;

struct mpool {
	struct media_class *mc[MCLASS_MAX];

	struct mdc         *mdc_root;

	char                name[64];
};

#endif /* MPOOL_H */

