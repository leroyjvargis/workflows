/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <ftw.h>

#include <hse_util/event_counter.h>
#include <hse_util/logging.h>
#include <hse_util/page.h>

#include "omf.h"
#include "mclass.h"
#include "mblock_fset.h"
#include "mblock_file.h"

#define MBLOCK_FSET_HDR_LEN    (4096)

/**
 * struct mblock_fset - mblock fileset instance
 *
 * @mc:        media class handle
 * @filev:     vector of mblock file handles
 * @fcnt:      mblock file count
 * @metafd:    fd of the fileset meta file
 * @meta_name: fileset meta file name
 */
struct mblock_fset {
    struct media_class  *mc;

    atomic64_t           fidx;
    struct mblock_file **filev;
    int                  fcnt;

    char                *maddr;
    size_t               metasz;
    int                  metafd;
    char                 mname[32];
};

static void
mblock_metahdr_init(struct mblock_fset *mbfsp, struct mblock_metahdr *mh)
{
    mh->vers = MBLOCK_METAHDR_VERSION;
    mh->magic = MBLOCK_METAHDR_MAGIC;
    mh->mcid = mclass_id(mbfsp->mc);
    mh->fcnt = mbfsp->fcnt;
    mh->blkbits = MBID_BLOCK_BITS;
    mh->mcbits = MBID_MCID_BITS;
}

static bool
mblock_metahdr_validate(struct mblock_fset *mbfsp, struct mblock_metahdr *mh)
{
    return (mh->vers == MBLOCK_METAHDR_VERSION) &&
        (mh->magic == MBLOCK_METAHDR_MAGIC) &&
        (mh->mcid == mclass_id(mbfsp->mc)) &&
        (mh->fcnt == mbfsp->fcnt) &&
        (mh->blkbits == MBID_BLOCK_BITS) &&
        (mh->mcbits == MBID_MCID_BITS);
}

static void
mblock_fset_meta_get(
    struct mblock_fset  *mbfsp,
    int                  fidx,
    char               **maddr,
    off_t               *off)
{
    *off = MBLOCK_FSET_HDR_LEN + (fidx * mblock_file_meta_len());
    *maddr = mbfsp->maddr + *off;
}

static merr_t
mblock_fset_meta_format(struct mblock_fset *mbfsp)
{
    struct mblock_metahdr mh = {};
    char *addr;
    int rc, i;

    mblock_metahdr_init(mbfsp, &mh);

    addr = mbfsp->maddr;

    /* Format meta header */
    omf_mblock_metahdr_pack_htole(&mh, addr);
    rc = msync(addr, MBLOCK_FSET_HDR_LEN, MS_SYNC);
    if (ev(rc < 0))
        return merr(errno);

    for (i = 0; i < mbfsp->fcnt; i++) {
        merr_t err;

        err = mblock_file_meta_format(mbfsp->filev[i]);
        if (ev(err))
            return err;
    }

    return 0;
}

static merr_t
mblock_fset_meta_load(struct mblock_fset *mbfsp)
{
    struct mblock_metahdr mh = {};
    int i;
    bool valid;

    /* Validate meta header */
    omf_mblock_metahdr_unpack_letoh(&mh, mbfsp->maddr);
    valid = mblock_metahdr_validate(mbfsp, &mh);
    if (!valid)
        return merr(EBADMSG);

    for (i = 0; i < mbfsp->fcnt; i++) {
        merr_t err;

        err = mblock_file_meta_load(mbfsp->filev[i]);
        if (ev(err))
            return err;
    }

    return 0;
}

/* Init metadata file that persists mblocks in the data files */
static merr_t
mblock_fset_meta_open(struct mblock_fset *mbfsp)
{
    int fd, flags, prot, rc, dirfd, i;
    merr_t err;
    size_t metasz;
    char *addr;
    bool format = false;

    if (ev(!mbfsp))
        return merr(EINVAL);

    snprintf(mbfsp->mname, sizeof(mbfsp->mname),
             "%s-%d", "mblock-meta", mclass_id(mbfsp->mc));

    dirfd = mclass_dirfd(mbfsp->mc);

    /* Determine if metadata file needs formatting. */
    rc = faccessat(dirfd, mbfsp->mname, F_OK, 0);
    if (rc < 0 && errno == ENOENT)
        format = true;

    fd = openat(dirfd, mbfsp->mname, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        err = merr(errno);
        hse_elog(HSE_ERR "open/create meta file failed, mclass dir %s: @@e",
                 err, mclass_dpath(mbfsp->mc));
    }

    mbfsp->metafd = fd;

    metasz = MBLOCK_FSET_HDR_LEN + (mbfsp->fcnt * mblock_file_meta_len());
    mbfsp->metasz = metasz;

    /* Preallocate metadata file. */
    rc = fallocate(fd, 0, 0, metasz);
    if (ev(rc < 0)) {
        err = merr(rc);
        goto errout;
    }

    flags = MAP_SHARED;
    prot = PROT_READ | PROT_WRITE;

    addr = mmap(NULL, metasz, prot, flags, fd, 0);
    if (ev(addr == MAP_FAILED)) {
        err = merr(errno);
        goto errout;
    }
    mbfsp->maddr = addr;

    for (i = 0; i < mbfsp->fcnt; i++) {
        char *addr;
        off_t off;

        mblock_fset_meta_get(mbfsp, i, &addr, &off);

        mblock_file_meta_init(mbfsp->filev[i], addr, mbfsp->metafd, off);
    }

    if (format)
        err = mblock_fset_meta_format(mbfsp);
    else
        err = mblock_fset_meta_load(mbfsp);
    if (ev(err))
        goto errout;

    return 0;

errout:
    if (mbfsp->maddr)
        munmap(mbfsp->maddr, metasz);
    close(fd);

    return err;
}

static void
mblock_fset_meta_close(struct mblock_fset *mbfsp)
{
    msync(mbfsp->maddr, mbfsp->metasz, MS_SYNC);
    munmap(mbfsp->maddr, mbfsp->metasz);
    close(mbfsp->metafd);
}

static void
mblock_fset_meta_remove(const char *dpath, int mcid)
{
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/%s-%d", dpath, "mblock-meta", mcid);

    remove(path);
}

merr_t
mblock_fset_open(struct media_class *mc, int flags, struct mblock_fset **handle)
{
    struct mblock_fset *mbfsp;

    size_t sz;
    merr_t err;
    int    i = 0;

    if (ev(!mc || !handle))
        return merr(EINVAL);

    sz = sizeof(*mbfsp) + MBLOCK_FSET_FILES_DEFAULT * sizeof(void *);

    mbfsp = calloc(1, sz);
    if (ev(!mbfsp))
        return merr(ENOMEM);

    mbfsp->mc = mc;
    atomic64_set(&mbfsp->fidx, 0);
    mbfsp->fcnt = MBLOCK_FSET_FILES_DEFAULT;
    mbfsp->filev = (void *)(mbfsp + 1);

    for (i = 0; i < mbfsp->fcnt; i++) {
        char name[32];

        snprintf(name, sizeof(name), "%s-%d-%d", "mblock-data", mclass_id(mc), i + 1);

        err = mblock_file_open(mbfsp, mclass_dirfd(mc), mclass_id(mc), i + 1, name,
                               flags, &mbfsp->filev[i]);
        if (ev(err))
            goto err_exit;
    }

    err = mblock_fset_meta_open(mbfsp);
    if (ev(err))
        goto err_exit;

    *handle = mbfsp;

    return 0;

err_exit:
    while (i-- > 0)
        mblock_file_close(mbfsp->filev[i]);
    free(mbfsp);

    return err;
}

void
mblock_fset_close(struct mblock_fset *mbfsp)
{
    int i;

    if (ev(!mbfsp))
        return;

    i = mbfsp->fcnt;
    while (i-- > 0)
        mblock_file_close(mbfsp->filev[i]);

    mblock_fset_meta_close(mbfsp);

    free(mbfsp);
}

static int
mblock_fset_removecb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    if (strstr(path, "mblock-data"))
        return remove(path);

    return 0;
}

void
mblock_fset_remove(struct mblock_fset *mbfsp)
{
    const char *dpath;
    int mcid;

    dpath = mclass_dpath(mbfsp->mc);
    mcid = mclass_id(mbfsp->mc);

    mblock_fset_close(mbfsp);

    nftw(dpath, mblock_fset_removecb, MBLOCK_FSET_FILES_DEFAULT, FTW_DEPTH | FTW_PHYS);

    mblock_fset_meta_remove(dpath, mcid);
}

merr_t
mblock_fset_alloc(struct mblock_fset *mbfsp, int mbidc, uint64_t *mbidv)
{
    struct mblock_file *mbfp;

    merr_t err;
    int fidx;
    int retries;

    if (ev(!mbfsp || !mbidv))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    retries = mbfsp->fcnt - 1;

    do {
        fidx = atomic64_fetch_add(1, &mbfsp->fidx) % mbfsp->fcnt;

        mbfp = mbfsp->filev[fidx];
        assert(mbfp);

        err = mblock_file_alloc(mbfp, mbidc, mbidv);
        if (merr_errno(err) != ENOSPC)
            break;
    } while (retries--);

    return err;
}

merr_t
mblock_fset_commit(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->fcnt))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    return mblock_file_commit(mbfp, mbidv, mbidc);
}

merr_t
mblock_fset_abort(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->fcnt))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    return mblock_file_abort(mbfp, mbidv, mbidc);
}

merr_t
mblock_fset_delete(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->fcnt))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    return mblock_file_delete(mbfp, mbidv, mbidc);
}

merr_t
mblock_fset_find(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->fcnt))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    return mblock_file_find(mbfp, mbidv, mbidc);
}

merr_t
mblock_fset_write(
    struct mblock_fset *mbfsp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
    off_t               off)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp) || file_id(mbid) > mbfsp->fcnt)
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_file_write(mbfp, mbid, iov, iovc, off);
}

merr_t
mblock_fset_read(
    struct mblock_fset *mbfsp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
    off_t               off)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp || file_id(mbid) > mbfsp->fcnt))
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_file_read(mbfp, mbid, iov, iovc, off);
}
