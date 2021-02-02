/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
/*
 * Storage manager interface for HSE
 */

#ifndef MPOOL_MCLASS_H
#define MPOOL_MCLASS_H

#include <dirent.h>

#include <hse_util/hse_err.h>

#define MCLASS_MAX              (1 << 2)    /* 2-bit for mclass-id */

struct mblock_fset;
struct mpool;

enum mclass_id {
	MCID_CAPACITY = 0,
	MCID_STAGING  = 1,
	MCID_MAX      = 2,
};

struct media_class {
	enum mclass_id          mcid;

	char                    dpath[PATH_MAX];
	DIR                    *dirp;

	struct mblock_fset     *fset;
};

merr_t
mclass_open(struct mpool *mp, enum mclass_id mcid, const char *dpath, struct media_class **handle);

merr_t
mclass_close(struct media_class *mc);

void
mclass_destroy(struct media_class *mc);

int
mclass_id(struct media_class *mc);

const char *
mclass_dpath(struct media_class *mc);

int
mclass_dirfd(struct media_class *mc);

#endif /* MPOOL_MCLASS_H */

