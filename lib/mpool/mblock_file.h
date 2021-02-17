/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MBLOCK_FILE_H
#define MPOOL_MBLOCK_FILE_H

#include <hse_util/hse_err.h>

#include "mclass.h"
#include "mblock.h"

#define MBID_UNIQ_SHIFT   (32)
#define MBID_RSVD_SHIFT   (26)
#define MBID_MCID_SHIFT   (24)
#define MBID_FILEID_SHIFT (16)

#define MBID_UNIQ_MASK    (0xffffffff00000000)
#define MBID_RSVD_MASK    (0x00000000fc000000)
#define MBID_MCID_MASK    (0x0000000003000000)
#define MBID_FILEID_MASK  (0x0000000000ff0000)
#define MBID_BLOCK_MASK   (0x000000000000ffff)

struct mblock_mmap;
struct mblock_rgnmap;
struct mblock_fset;
struct mblock_file;
struct io_ops;

/**
 * mblock_file_open() - open an mblock file
 *
 * @fs:    mblock fileset handle
 * @dirfd: mclass directory fd
 * @name:  file name
 * @flags: open flags
 * @handle(output): mblock file handle
 *
 */
merr_t
mblock_file_open(
    struct mblock_fset  *mbfsp,
    int                  dirfd,
    enum mclass_id       mcid,
    int                  fileid,
    char                *name,
    int                  flags,
    struct mblock_file **handle);

/**
 * mblock_file_close() - close an mblock file
 *
 * @mbfp: mblock file handle
 */
void
mblock_file_close(struct mblock_file *mbfp);

/**
 * mblock_file_alloc() - allocate a vector of mblock objects
 *
 * @mbfp:  mblock file handle
 * @mbidc: count of objects to allocate
 *
 * @mbidv (output): vector of mblock ids
 */
merr_t
mblock_file_alloc(struct mblock_file *mbfp, int mbidc, uint64_t *mbidv);

/**
 * mblock_file_commit() - commit a vector of mblock objects
 *
 * @mbfp:  mblock file handle
 * @mbidv  vector of mblock ids
 * @mbidc: count of mblock ids
 */
merr_t
mblock_file_commit(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc);

/**
 * mblock_file_abort() - abort a vector of mblock objects
 *
 * @mbfp:  mblock file handle
 * @mbidv  vector of mblock ids
 * @mbidc: count of mblock ids
 */
merr_t
mblock_file_abort(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc);

/**
 * mblock_file_delete() - destroy a vector of mblock objects
 *
 * @mbfp:  mblock file handle
 * @mbidv  vector of mblock ids
 * @mbidc: count of mblock ids
 */
merr_t
mblock_file_delete(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc);

/**
 * mblock_file_read() - read an mblock object
 *
 * @mbfp:   mblock file handle
 * @mbid:   mblock id
 * @iov:    iovec ptr
 * @iovc:   iov count
 * @off:    offset
 */
merr_t
mblock_file_read(
    struct mblock_file *mbfp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
    off_t               off);

/**
 * mblock_file_write() - write an mblock object
 *
 * @mbfp:   mblock file handle
 * @mbid:   mblock id
 * @iov:    iovec ptr
 * @iovc:   iov count
 * @off:    offset
 */
merr_t
mblock_file_write(
    struct mblock_file *mbfp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
    off_t               off);

merr_t
mblock_file_find(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc);

#endif /* MPOOL_MBLOCK_FILE_H */

