/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
/*
 * Storage manager interface for HSE
 */

#ifndef MPOOL_MBLOCK_H
#define MPOOL_MBLOCK_H

#include <hse_util/hse_err.h>

#include <mpool/mpool2.h>

#define MBLOCK_FS_FCNT_MAX      (1 << 8)    /* 8-bit for file-id */
#define MBLOCK_FS_FCNT_DFLT      32
#define MBLOCK_FS_FSIZE_MAX     (1ULL << 11) /* In GiB */

struct mblock_mmap;
struct mblock_smap;
struct mblock_fset;
struct mblock_file;
struct file_ops;

struct mblock_fset {
	struct media_class     *mc;

	struct mblock_file    **filev;
	int                     filec;

	atomic_t                curfid;

	int                     meta_fd;
	char                    meta_name[32];
};

merr_t
mblock_fset_open(struct media_class *mc, struct mblock_fset **mfs);

void
mblock_fset_close(struct mblock_fset *mfs);

void
mblock_fset_remove(struct mblock_fset *mfs);

struct mblock_file {
	struct mblock_fset     *fset;
	struct file_ops        *fops;

	size_t                  maxsz;

	off_t                   meta_soff;
	size_t                  meta_len;

	struct mblock_smap     *smap;
	struct mblock_map      *mmap;

	int                     fd;
	char                    name[32];
};

merr_t
mblock_file_open(struct mblock_fset *mfs, int dirfd, char *name, struct mblock_file **handle);

void
mblock_file_close(struct mblock_file *mf);

merr_t
mblock_allocv(struct mblock_file *mf, uint64_t *mbidv, int mbidc);

merr_t
mblock_commitv(struct mblock_file *mf, uint64_t *mbidv, int mbidc);

merr_t
mblock_abortv(struct mblock_file *mf, uint64_t *mbidv, int mbidc);

merr_t
mblock_destroyv(struct mblock_file *mf, uint64_t *mbidv, int mbidc);

merr_t
mblock_read(struct mblock_file *mf, uint64_t mbid, const struct iovec *iov, int iovc,
	    off_t offset);

merr_t
mblock_write(struct mblock_file *mf, uint64_t mbid, const struct iovec *iov, int iovc,
	     off_t offset);

#endif /* MPOOL_MBLOCK_H */

