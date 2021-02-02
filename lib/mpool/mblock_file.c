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
#include <ftw.h>

#include <hse_util/string.h>
#include <hse_util/logging.h>
#include <hse_util/event_counter.h>

#include "mclass.h"
#include "mblock.h"

merr_t
mblock_file_open(struct mblock_fset *mfs, int dirfd, char *name, struct mblock_file **handle)
{
    struct mblock_file *mf;

    int fd, rc;
    merr_t err;

    if (ev(!mfs || !name || !handle))
        return merr(EINVAL);

    mf = calloc(1, sizeof(*mf));
    if (ev(!mf))
        return merr(ENOMEM);

    mf->fset = mfs;
    mf->maxsz = MBLOCK_FS_FSIZE_MAX;
    strlcpy(mf->name, name, sizeof(mf->name));

    fd = openat(dirfd, name, O_RDWR | O_DIRECT | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        err = merr(errno);
        hse_elog(HSE_ERR "open/create data file failed, mclass dir %s, file name %s: @@e",
                 err, mclass_dpath(mfs->mc), name);
        goto err_exit;
    }

    /* ftruncate to the maximum size to make it a sparse file */
    rc = ftruncate(fd, MBLOCK_FS_FSIZE_MAX << 30);
    if (rc < 0) {
        err = merr(errno);
        close(fd);
        hse_elog(HSE_ERR "Truncating data file failed, mclass dir %s: file name %s: @@e",
                 err, mclass_dpath(mfs->mc), name);
        goto err_exit;
    }

    mf->fd = fd;

    *handle = mf;

    return 0;

err_exit:
    free(mf);

    return err;
}

void
mblock_file_close(struct mblock_file *mf)
{
    if (!mf)
        return;

    close(mf->fd);
}
