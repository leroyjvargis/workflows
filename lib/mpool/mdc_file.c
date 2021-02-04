/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <hse_util/string.h>
#include <hse_util/logging.h>
#include <hse_util/event_counter.h>

#include "mdc_file.h"
#include "omf.h"

static void
mdc_loghdr_init(struct mdc_loghdr *lh)
{
    lh->vers = MDC_LOGHDR_VERSION;
    lh->magic = MDC_LOGHDR_MAGIC;
    lh->rsvd = 0;
    lh->gen = 0;
    /* [HSE_REVISIT] : calculate CRC */
    lh->crc = 0;
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
        hse_elog(HSE_ERR "create mdc file failed, name %s: @@e", err, name);
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
    struct mdc_loghdr_omf lhomf;
    char name[32];
    size_t cc, len;
    merr_t err = 0;
    int fd;

    mdc_filename_gen(name, sizeof(name), logid);

    fd = openat(dirfd, name, O_RDWR);
    if (fd < 0) {
        err = merr(errno);
        hse_elog(HSE_ERR "Commit mdc file failed, name %s: @@e", err, name);
        return err;
    }

    mdc_loghdr_init(&lh);

    err = omf_mdc_loghdr_pack_htole(&lh, (char *)&lhomf);
    if (ev(err))
        goto errout;

    len = sizeof(lhomf);
    cc = pwrite(fd, &lhomf, sizeof(lhomf), 0);
    if (cc != len) {
        err = merr(errno);
        goto errout;
    }

errout:
    close(fd);

    return err;
}
