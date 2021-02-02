/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MDC_H
#define MPOOL_MDC_H

#include <hse_util/mutex.h>

struct media_class;
struct mdc_file;
struct io_ops;

struct mpool_mdc {
	struct mutex           lock;
	struct mdc_file       *mfp1;
	struct mdc_file       *mfp2;
	struct mdc_file       *mfpa;
	struct media_class    *mc;

	struct mpool          *mp;

	uint64_t               magic;
	int                    vers;
};

struct mdc_loghdr {
	uint32_t              crc;
	uint32_t              vers;
	uint32_t              magic;
	uint32_t              rsvd;
	uint64_t              gen;
};

struct mdc_file {
	struct mpool_mdc      *mdc;

	struct mdc_loghdr      lh;
	size_t                 size;

	uint64_t               logid;

	int                    dirfd;
	int                    fd;
	char                   name[32];

	struct io_ops         *io;
};

struct mdc_rechdr {
	uint32_t               crc;
	uint32_t               size;
};

#endif /* MPOOL_MDC_H */

