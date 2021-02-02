/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MDC_H
#define MPOOL_MDC_H

struct media_class;
struct mdc_file;
struct io_ops;

struct mdc {
	struct mdc_file       *mf1;
	struct mdc_file       *mf2;

	struct media_class    *mc;

	uint64_t               magic;
	int                    vers;
};

struct mdc_file {
	struct mdc            *mdc;

	int64_t                gen;
	size_t                 size;

	int                    dirfd;
	int                    fd;
	char                   name[32];

	struct io_ops         *io;
};

#endif /* MPOOL_MDC_H */

