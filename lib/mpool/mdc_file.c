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

#include <hse_util/string.h>
#include <hse_util/logging.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>

#include "mdc.h"
#include "mdc_file.h"
#include "omf.h"
#include "io.h"

struct mpool_mdc;

static merr_t
loghdr_update(int fd, struct mdc_loghdr *lh, uint64_t gen)
{
    struct mdc_loghdr_omf lhomf;

    merr_t err;
    size_t len;
    int cc, rc;

    lh->vers = MDC_LOGHDR_VERSION;
    lh->magic = MDC_LOGHDR_MAGIC;
    lh->rsvd = 0;
    lh->gen = gen;
    /* [HSE_REVISIT] : calculate CRC */
    lh->crc = 0;

    err = omf_mdc_loghdr_pack_htole(lh, (char *)&lhomf);
    if (ev(err))
        return err;

    len = sizeof(lhomf);
    cc = pwrite(fd, &lhomf, len, 0);
    if (cc != len)
        return merr(errno);

    rc = fsync(fd);
    if (rc < 0)
        return merr(errno);

    return 0;
}

static merr_t
loghdr_validate(struct mdc_file *mfp, uint64_t *gen)
{
    struct mdc_loghdr *lh;
    bool valid;

    lh = &mfp->lh;

    omf_mdc_loghdr_unpack_letoh(lh, (const char *)mfp->addr);

    valid = (lh->vers == MDC_LOGHDR_VERSION && lh->magic == MDC_LOGHDR_MAGIC);

    if (valid) {
        /* TODO: Calculate CRC and verify lh->crc */
        ;
    }

    if (gen)
        *gen = lh->gen;

    return valid ? 0 : merr(EBADMSG);
}

static merr_t
logrec_validate(char *addr, size_t *recsz)
{
    struct mdc_rechdr rh;

    omf_mdc_rechdr_unpack_letoh(&rh, (const char *)addr);

    if (rh.size == 0) {
        *recsz = 0;
        return merr(ENOMSG);
    }

    /* TODO: Calculate CRC and verify rh.crc */

    *recsz = rh.size;

    return 0;
}

merr_t
mdc_file_create(int dirfd, uint64_t logid, int flags, int mode, size_t capacity)
{
    int fd, rc;
    merr_t err = 0;
    char name[32];

    mdc_filename_gen(name, sizeof(name), logid);

    fd = openat(dirfd, name, flags, mode);
    if (fd < 0) {
        err = merr(errno);
        return err;
    }

    rc = fallocate(fd, 0, 0, capacity);
    if (rc < 0) {
        err = merr(errno);
        mdc_file_destroy(dirfd, logid);
        hse_elog(HSE_ERR "Pre-allocating mdc file 1 failed, name %s: @@e", err, name);
    }

    close(fd);

    return err;
}

merr_t
mdc_file_destroy(int dirfd, uint64_t logid)
{
    char name[32];
    int rc;

    mdc_filename_gen(name, sizeof(name), logid);

    rc = unlinkat(dirfd, name, 0);
    if (rc < 0)
        return merr(errno);

    return 0;
}

/* At commit, the log header of both MDC files are initialized. */
merr_t
mdc_file_commit(int dirfd, uint64_t logid)
{
    struct mdc_loghdr lh;
    char name[32];
    merr_t err = 0;
    int fd;

    mdc_filename_gen(name, sizeof(name), logid);

    fd = openat(dirfd, name, O_RDWR);
    if (fd < 0) {
        err = merr(errno);
        hse_elog(HSE_ERR "Commit mdc file failed, name %s: @@e", err, name);
        return err;
    }

    err = loghdr_update(fd, &lh, 0);

    close(fd);

    return err;
}

static merr_t
mdc_file_mmap(struct mdc_file *mfp)
{
    int flags, prot;

    if (ev(!mfp))
        return merr(EINVAL);

    flags = MAP_SHARED;
    prot = PROT_READ | PROT_WRITE;

    mfp->addr = mmap(NULL, mfp->size, prot, flags, mfp->fd, 0);
    if (mfp->addr == MAP_FAILED)
        return merr(errno);

    return 0;
}

static merr_t
mdc_file_unmap(struct mdc_file *mfp)
{
    int rc;

    rc = munmap(mfp->addr, mfp->size);
    if (rc < 0)
        return merr(errno);

    return 0;
}

static merr_t
mdc_file_validate(struct mdc_file *mfp, uint64_t *gen)
{
    char *addr;
    merr_t err;
    int rc;
    int rhlen;

    if (ev(!mfp))
        return merr(EINVAL);

    addr = mfp->addr;

    /* The MDC file will now be read sequentially. Pass this hint to VMM via madvise. */
    rc = madvise(addr, mfp->size, MADV_SEQUENTIAL);
    if (rc < 0)
        hse_log(HSE_WARNING "madvise mdc file %s %p failed", mfp->name, addr);

    /* Step 1: validate log header */
    err = loghdr_validate(mfp, gen);
    if (ev(err))
        goto errout;

    addr += MDC_LOGHDR_LEN; /* move past the log header */

    rhlen = omf_mdc_rechdr_len();

    /* Step 2: validate log records */
    do {
        size_t recsz;

        err = logrec_validate(addr, &recsz);
        if (err) {
            if (merr_errno(err) == ENOMSG) { /* End of log */
                err = 0;
                mfp->woff = addr - mfp->addr;
                break;
            }
            goto errout;
        }

        addr += (rhlen + recsz);
    } while (true);

errout:
    madvise(mfp->addr, mfp->size, MADV_DONTNEED);

    return err;
}

merr_t
mdc_file_size(int fd, size_t *size)
{
    struct stat s;
    int rc;

    rc = fstat(fd, &s);
    if (rc < 0)
        return merr(errno);

    *size = s.st_size;

    return 0;
}

merr_t
mdc_file_open(struct mpool_mdc *mdc, uint64_t logid, uint64_t *gen, struct mdc_file **handle)
{
    struct mdc_file *mfp;

    int fd, dirfd;
    merr_t err;
    char name[32];

    if (ev(!mdc))
        return merr(EINVAL);

    mdc_filename_gen(name, sizeof(name), logid);
    dirfd = mclass_dirfd(mdc_mclass_get(mdc));

    fd = openat(dirfd, name, O_RDWR);
    if (ev(fd < 0)) {
        err = merr(errno);
        return err;
    }

    mfp = calloc(1, sizeof(*mfp));
    if (ev(!mfp)) {
        err = merr(ENOMEM);
        goto err_exit2;
    }

    err = mdc_file_size(fd, &mfp->size);
    if (ev(err))
        goto err_exit1;

    mfp->mdc = mdc;
    mfp->logid = logid;
    mfp->fd = fd;
    mfp->io = &io_sync_ops;
    strlcpy(mfp->name, name, sizeof(mfp->name));
    mfp->roff = MDC_LOGHDR_LEN;
    mfp->raoff = MDC_RA_BYTES;

    err = mdc_file_mmap(mfp);
    if (ev(err))
        goto err_exit1;

    err = mdc_file_validate(mfp, gen);
    if (ev(err)) {
        mdc_file_unmap(mfp);
        goto err_exit1;
    }

    *handle = mfp;

    return 0;

err_exit1:
    free(mfp);

err_exit2:
    close(fd);

    return err;
}

merr_t
mdc_file_close(struct mdc_file *mfp)
{
    if (ev(!mfp))
        return merr(EINVAL);

    mdc_file_unmap(mfp);

    close(mfp->fd);

    free(mfp);

    return 0;
}

merr_t
mdc_file_empty(struct mdc_file *mfp, bool *empty)
{
    char *addr;
    merr_t err;
    size_t recsz;

    if (ev(!mfp || !empty))
        return merr(EINVAL);

    *empty = false;
    addr = mfp->addr + MDC_LOGHDR_LEN;

    err = logrec_validate(addr, &recsz);
    if (err && recsz == 0) {
        assert(merr_errno(err) == ENOMSG);
        *empty = true;
    }

    return 0;
}

merr_t
mdc_file_erase(struct mdc_file *mfp, uint64_t newgen)
{
    merr_t err;
    int rc;

    if (ev(!mfp))
        return merr(EINVAL);

    err = loghdr_update(mfp->fd, &mfp->lh, newgen);
    if (ev(err))
        return err;

    rc = fallocate(mfp->fd, FALLOC_FL_ZERO_RANGE, MDC_LOGHDR_LEN, mfp->size - MDC_LOGHDR_LEN);
    if (rc < 0)
        err = merr(errno);

    return err;
}

merr_t
mdc_file_erase_byid(int dirfd, uint64_t logid, uint64_t newgen)
{
    struct mdc_loghdr lh;
    merr_t err = 0;
    int fd, rc;
    char name[32];
    size_t sz;

    mdc_filename_gen(name, sizeof(name), logid);

    fd = openat(dirfd, name, O_RDWR);
    if (fd < 0) {
        err = merr(errno);
        return err;
    }

    err = mdc_file_size(fd, &sz);
    if (ev(err))
        goto errout;

    err = loghdr_update(fd, &lh, newgen);
    if (ev(err))
        goto errout;

    rc = fallocate(fd, FALLOC_FL_ZERO_RANGE, MDC_LOGHDR_LEN, sz - MDC_LOGHDR_LEN);
    if (rc < 0)
        err = merr(errno);

errout:
    close(fd);

    return err;
}

merr_t
mdc_file_gen(struct mdc_file *mfp, uint64_t *gen)
{
    if (ev(!mfp || !gen))
        return merr(EINVAL);

    *gen = mfp->lh.gen;

    return 0;
}

merr_t
mdc_file_exists(int dirfd, uint64_t logid1, uint64_t logid2, bool *exist)
{
    char name[32];
    int fd;
    merr_t err;

    *exist = false;

    mdc_filename_gen(name, sizeof(name), logid1);
    fd = openat(dirfd, name, O_RDONLY);
    if (fd < 0) {
        err = merr(errno);
        if (merr_errno(err) == ENOENT)
            return 0;
        return err;
    }
    close(fd);

    mdc_filename_gen(name, sizeof(name), logid2);
    fd = openat(dirfd, name, O_RDONLY);
    if (fd < 0) {
        err = merr(errno);
        if (merr_errno(err) == ENOENT)
            return 0;
        return err;
    }
    close(fd);

    *exist = true;

    return 0;
}

merr_t
mdc_file_sync(struct mdc_file *mfp)
{
    int rc;

    if (ev(!mfp))
        return merr(EINVAL);

    rc = msync(mfp->addr, mfp->woff, MS_SYNC);
    if (rc < 0)
        return merr(errno);

    return 0;
}

merr_t
mdc_file_rewind(struct mdc_file *mfp)
{
    if (ev(!mfp))
        return merr(EINVAL);

    mfp->roff = MDC_LOGHDR_LEN;
    mfp->raoff = MDC_RA_BYTES;

    return 0;
}

merr_t
mdc_file_usage(struct mdc_file *mfp, size_t *usage)
{
    if (ev(!mfp || !usage))
        return merr(EINVAL);

    *usage = mfp->woff;

    return 0;
}

merr_t
mdc_file_read(struct mdc_file *mfp, void *data, size_t len, size_t *rdlen)
{
    struct mdc_rechdr rh;
    char *addr;
    int rhlen, rc;

    if (ev(!mfp || !data))
        return merr(EINVAL);

    if (mfp->roff == MDC_LOGHDR_LEN) { /* First read */
        rc = madvise(mfp->addr, mfp->woff, MADV_SEQUENTIAL);
        ev(rc);
    }

    addr = mfp->addr + mfp->roff;

    if (mfp->roff > mfp->raoff) {
        rc = madvise(addr - MDC_RA_BYTES, MDC_RA_BYTES, MADV_DONTNEED);
        ev(rc);

        mfp->raoff <<= 1;
    }

    omf_mdc_rechdr_unpack_letoh(&rh, (const char *)addr);

    rhlen = omf_mdc_rechdr_len();
    addr += rhlen;

    if (rdlen)
        *rdlen = rh.size;

    if (rh.size > len)
        return merr(EOVERFLOW);

    /* TODO: validate CRC */
    memcpy(data, addr, rh.size);

    mfp->roff += (rhlen + rh.size);

    return 0;
}

merr_t
mdc_file_append(struct mdc_file *mfp, void *data, size_t len, bool sync)
{
    struct mdc_rechdr rh;
    char *addr;
    size_t rhlen;

    if (ev(!mfp || !data))
        return merr(EINVAL);

    rhlen = omf_mdc_rechdr_len();
    addr = mfp->addr + mfp->woff;

    rh.crc = 0; /* TODO: Calculate CRC */
    rh.size = len;

    omf_mdc_rechdr_pack_htole(&rh, addr);
    mfp->woff += rhlen;
    addr += rhlen;

    memcpy(addr, data, len);
    mfp->woff += len;

    if (sync) {
        int rc;

        rc = msync(mfp->addr, mfp->woff, MS_SYNC);
        if (rc < 0) {
            mfp->woff -= (rhlen + len);
            return merr(errno);
        }
    }

    return 0;
}
