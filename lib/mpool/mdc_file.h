/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MDC_FILE_H
#define MPOOL_MDC_FILE_H

#include <stdio.h>

#include <hse_util/hse_err.h>

#include "mclass.h"

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

	uint64_t               logid;
	int                    dirfd;
	int                    fd;

	off_t                  woff;
	off_t                  roff;
	size_t                 size;

	struct io_ops         *io;
	char                   name[32];
};

struct mdc_rechdr {
	uint32_t               crc;
	uint32_t               size;
};

merr_t
mdc_file_create(int dirfd, uint64_t logid, int flags, int mode, size_t capacity);

merr_t
mdc_file_destroy(int dirfd, uint64_t logid);

merr_t
mdc_file_commit(int dirfd, uint64_t logid);

static inline uint64_t
logid_make(u8 fid, enum mclass_id mcid, uint32_t magic)
{
    return (uint64_t)fid << 34 | (uint64_t)mcid << 32 | magic;
}

static inline uint32_t
logid_magic(uint64_t logid)
{
    return logid & UINT_MAX;
}

static inline uint8_t
logid_mcid(uint64_t logid)
{
    return (logid >> 32) & 3;
}

static inline uint8_t
logid_fid(uint64_t logid)
{
    return (logid >> 34) & 1;
}

static inline bool
logid_valid(uint64_t logid)
{
    return logid != 0; /* TODO: add more validations */
}

static inline bool
logids_valid(uint64_t logid1, uint64_t logid2)
{
    return (logid_valid(logid1) && logid_valid(logid2));
}

static inline void
mdc_filename_gen(char *buf, size_t buflen, uint64_t logid)
{
    snprintf(buf, buflen, "%s-%lx", "mdc", logid);
}

#endif /* MPOOL_MDC_FILE_H */
