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

#include <3rdparty/rbtree.h>

#include <hse_util/mutex.h>
#include <hse_util/string.h>
#include <hse_util/slab.h>
#include <hse_util/logging.h>
#include <hse_util/event_counter.h>

#include "mblock_file.h"
#include "io.h"

/**
 * struct mblock_rgn -
 * @rgn_node:  rb-tree linkage
 * @rgn_start: first available key
 * @rgn_end:   last available key (not inclusive)
 */
struct mblock_rgn {
	struct rb_node      rgn_node;
	uint32_t            rgn_start;
	uint32_t            rgn_end;
};

/**
 * struct mblock_rgnmap -
 */
struct mblock_rgnmap {
	struct mutex        rm_lock;
	struct rb_root      rm_root;
	struct rb_node     *rm_cur;

	struct kmem_cache  *rm_cache __aligned(SMP_CACHE_BYTES);
};

/**
 * struct mblock_file - mblock file handle (one per file)
 *
 * @mbfsp: reference to the fileset handle
 * @smap:  space map
 * @mmap:  mblock map
 * @io:    io handle for sync/async rw ops
 *
 * maxsz: maximum file size (2TiB with 16-bit block offset)
 *
 * meta_soff: start offset in the fset meta file
 * meta_len:  length of the metadata region for this file
 *
 * fd:   file handle
 * name: file name
 *
 */
struct mblock_file {
    struct mblock_rgnmap    rgnmap;
    struct mblock_fset     *mbfsp;
    struct mblock_map      *mmap;
    const struct io_ops    *io;

    size_t                  maxsz;

    off_t                   meta_soff;
    size_t                  meta_len;

    enum mclass_id          mcid;
    atomic_t                uniq;
    int                     fileid;

    int                     fd;
    char                    name[32];
};

static merr_t
mblock_rgnmap_init(
    struct mblock_file *mbfp,
    const char         *name)
{
    struct kmem_cache    *rmcache = NULL;
    struct mblock_rgnmap *rgnmap;
    struct mblock_rgn    *rgn;

    uint32_t rmax;

    rmcache = kmem_cache_create(name, sizeof(*rgn), __alignof(*rgn), 0, NULL);
    if (ev(!rmcache))
        return merr(ENOMEM);

    rgnmap = &mbfp->rgnmap;
    mutex_init(&rgnmap->rm_lock);
    rgnmap->rm_root = RB_ROOT;

    rgn = kmem_cache_alloc(rmcache);
    if (!rgn) {
        kmem_cache_destroy(rmcache);
        return merr(ENOMEM);
    }

    rgn->rgn_start = 1;
    rmax = (mbfp->maxsz << 10) / MBLOCK_SIZE_MB;
    rgn->rgn_end = rmax + 1;

    mutex_lock(&rgnmap->rm_lock);
    rb_link_node(&rgn->rgn_node, NULL, &rgnmap->rm_root.rb_node);
    rb_insert_color(&rgn->rgn_node, &rgnmap->rm_root);
    mutex_unlock(&rgnmap->rm_lock);

    rgnmap->rm_cache = rmcache;

    return 0;
}

merr_t
mblock_file_open(
    struct mblock_fset  *mbfsp,
    int                  dirfd,
    enum mclass_id       mcid,
    int                  fileid,
    char                *name,
    int                  flags,
    struct mblock_file **handle)
{
    struct mblock_file   *mbfp;

    int fd,  rc;
    merr_t   err;
    char     rname[32];

    if (ev(!mbfsp || !name || !handle))
        return merr(EINVAL);

    mbfp = calloc(1, sizeof(*mbfp));
    if (ev(!mbfp))
        return merr(ENOMEM);

    mbfp->maxsz = MBLOCK_FILE_SIZE_MAX;

    snprintf(rname, sizeof(rname), "%s-%d-%d", "rgnmap", mcid, fileid);
    err = mblock_rgnmap_init(mbfp, rname);
    if (ev(err))
        goto err_exit;

    mbfp->mbfsp = mbfsp;
    strlcpy(mbfp->name, name, sizeof(mbfp->name));

    mbfp->mcid = mcid;
    atomic_set(&mbfp->uniq, 1); /* TODO: initialize from metadata file */
    mbfp->fileid = fileid;

    if (flags == 0 || !(flags & (O_RDWR | O_RDONLY | O_WRONLY)))
        flags |= O_RDWR;

    flags &= O_RDWR | O_RDONLY | O_WRONLY | O_CREAT;

    if (flags & O_CREAT)
        flags |= O_EXCL;

    fd = openat(dirfd, name, flags | O_DIRECT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        err = merr(errno);
        hse_elog(HSE_ERR "open/create data file failed, file name %s: @@e", err, name);
        goto err_exit;
    }

    /* ftruncate to the maximum size to make it a sparse file */
    rc = ftruncate(fd, mbfp->maxsz << 30);
    if (rc < 0) {
        err = merr(errno);
        close(fd);
        hse_elog(HSE_ERR "Truncating data file failed, file name %s: @@e", err, name);
        goto err_exit;
    }

    mbfp->fd = fd;
    mbfp->io = &io_sync_ops;

    *handle = mbfp;

    return 0;

    err_exit:
    if (mbfp->rgnmap.rm_cache)
        kmem_cache_destroy(mbfp->rgnmap.rm_cache);

    free(mbfp);

    return err;
}

void
mblock_file_close(struct mblock_file *mbfp)
{
    struct mblock_rgnmap *rgnmap;
    struct mblock_rgn    *rgn, *next;

    if (!mbfp)
        return;

    rgnmap = &mbfp->rgnmap;

    rbtree_postorder_for_each_entry_safe(rgn, next, &rgnmap->rm_root, rgn_node) {
        kmem_cache_free(rgnmap->rm_cache, rgn);
    }

    close(mbfp->fd);

    free(mbfp);
}


static uint32_t
mblock_rgn_alloc(struct mblock_rgnmap *rgnmap)
{
    struct mblock_rgn  *rgn;
    struct rb_root     *root;
    struct rb_node     *node;
    uint32_t            key;

    rgn = NULL;
    key = 0;

    mutex_lock(&rgnmap->rm_lock);
    root = &rgnmap->rm_root;

    node = rgnmap->rm_cur;
    if (!node) {
        node = rb_first(root);
        rgnmap->rm_cur = node;
    }

    if (node) {
        rgn = rb_entry(node, struct mblock_rgn, rgn_node);

        key = rgn->rgn_start++;

        if (rgn->rgn_start < rgn->rgn_end) {
            rgn = NULL;
        } else {
            rgnmap->rm_cur = rb_next(node);
            rb_erase(&rgn->rgn_node, root);
        }
    }
    mutex_unlock(&rgnmap->rm_lock);

    if (rgn)
        kmem_cache_free(rgnmap->rm_cache, rgn);

    return key;
}

static merr_t
mblock_rgn_free(struct mblock_rgnmap *rgnmap, uint32_t key)
{
    struct mblock_rgn  *this, *that;
    struct rb_node    **new, *parent;
    struct rb_node     *nxtprv;
    struct rb_root     *root;

    merr_t err = 0;

    assert(rgnmap && key > 0);

    this = that = NULL;
    parent = NULL;
    nxtprv = NULL;

    mutex_lock(&rgnmap->rm_lock);
    root = &rgnmap->rm_root;
    new = &root->rb_node;

    while (*new) {
        this = rb_entry(*new, struct mblock_rgn, rgn_node);
        parent = *new;

        if (key < this->rgn_start) {
            if (key == this->rgn_start - 1) {
                --this->rgn_start;
                nxtprv = rb_prev(*new);
                new = NULL;
                break;
            }
            new = &(*new)->rb_left;
        } else if (key >= this->rgn_end) {
            if (key == this->rgn_end) {
                ++this->rgn_end;
                nxtprv = rb_next(*new);
                new = NULL;
                break;
            }
            new = &(*new)->rb_right;
        } else {
            new = NULL;
            err = merr(ENOENT);
            break;
        }
    }

    if (nxtprv) {
        that = rb_entry(nxtprv, struct mblock_rgn, rgn_node);

        if (this->rgn_start == that->rgn_end) {
            this->rgn_start = that->rgn_start;
            if (&that->rgn_node == rgnmap->rm_cur)
                rgnmap->rm_cur = &this->rgn_node;
            rb_erase(&that->rgn_node, root);
        } else if (this->rgn_end == that->rgn_start) {
            this->rgn_end = that->rgn_end;
            if (&that->rgn_node == rgnmap->rm_cur)
                rgnmap->rm_cur = rb_next(&that->rgn_node);
            rb_erase(&that->rgn_node, root);
        } else {
            that = NULL;
        }
    } else if (new) {
        struct mblock_rgn *rgn;

        rgn = kmem_cache_alloc(rgnmap->rm_cache);
        if (rgn) {
            rgn->rgn_start = key;
            rgn->rgn_end = key + 1;

            rb_link_node(&rgn->rgn_node, parent, new);
            rb_insert_color(&rgn->rgn_node, root);
        }
    }
    mutex_unlock(&rgnmap->rm_lock);

    if (that)
        kmem_cache_free(rgnmap->rm_cache, that);

    return err;
}

static merr_t
mblock_rgn_find(struct mblock_rgnmap *rgnmap, uint32_t key)
{
    struct mblock_rgn  *this;
    struct rb_node     *cur;

    assert(rgnmap && key > 0);

    mutex_lock(&rgnmap->rm_lock);
    cur = rgnmap->rm_root.rb_node;

    while (cur) {
        this = rb_entry(cur, struct mblock_rgn, rgn_node);

        if (key < this->rgn_start)
            cur = cur->rb_left;
        else if (key >= this->rgn_end)
            cur = cur->rb_right;
        else
            break;
    }

    mutex_unlock(&rgnmap->rm_lock);

    return cur ? merr(ENOENT) : 0;
}

merr_t
mblock_file_alloc(struct mblock_file *mbfp, int mbidc, uint64_t *mbidv)
{
    uint64_t mbid = 0;
    uint32_t block, uniq;

    if (ev(!mbfp || !mbidv))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    block = mblock_rgn_alloc(&mbfp->rgnmap);
    if (block == 0)
        return merr(ENOSPC);

    uniq = atomic_fetch_add(1, &mbfp->uniq);

    mbid |= ((uint64_t)uniq << MBID_UNIQ_SHIFT);
    mbid |= ((uint64_t)mbfp->mcid << MBID_MCID_SHIFT) & MBID_MCID_MASK;
    mbid |= ((uint64_t)mbfp->fileid << MBID_FILEID_SHIFT) & MBID_FILEID_MASK;
    mbid |= (block - 1) & MBID_BLOCK_MASK;

    /* TODO: Persist uniquifier on-media every 'n' allocations. */

    *mbidv = mbid;

    return 0;
}

merr_t
mblock_file_find(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc)
{
    uint32_t block;
    merr_t err;

    if (ev(!mbfp || !mbidv))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    block = block_id(*mbidv);

    err = mblock_rgn_find(&mbfp->rgnmap, block + 1);
    ev(err);

    return err;
}

merr_t
mblock_file_commit(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc)
{
    int rc;
    merr_t err;

    if (ev(!mbfp || !mbidv))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    err = mblock_file_find(mbfp, mbidv, mbidc);
    if (ev(err))
        return err;

    /* Sync file metadata and disk cache */
    rc = fsync(mbfp->fd);
    if (rc < 0)
        return merr(errno);

    /* TODO: Persist the allocation state of mblock ID on-media */

    return 0;
}

merr_t
mblock_file_abort(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc)
{
    uint32_t block;
    merr_t   err;

    if (ev(!mbfp || !mbidv))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    block = block_id(*mbidv);

    err = mblock_rgn_free(&mbfp->rgnmap, block + 1);
    if (ev(err))
        return err;

    return 0;
}

merr_t
mblock_file_delete(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc)
{
    uint64_t block;
    merr_t   err;
    int rc;

    if (ev(!mbfp || !mbidv))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    block = block_id(*mbidv);

    err = mblock_rgn_free(&mbfp->rgnmap, block + 1);
    if (ev(err))
        return err;

    /* Discard mblock */
    rc = fallocate(mbfp->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                   block_off(*mbidv), MBLOCK_SIZE_BYTES);
    ev(rc);

    /* TODO: Persist the allocation state of mblock ID on media */

    return 0;
}

merr_t
mblock_file_read(
    struct mblock_file *mbfp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
	off_t               off)
{
    uint64_t roff;
    bool verify = false; /* TODO: Toggle after adding persisting mblocks */

    if (ev(!mbfp || !iov))
        return merr(EINVAL);

    if (iovc == 0)
        return 0;

    /* TODO: Add offset and len validation */

    if (verify) {
        merr_t err;

        err = mblock_file_find(mbfp, &mbid, 1);
        if (ev(err))
            return err;
    }

    roff = block_off(mbid);
    roff += off;

    return mbfp->io->read(mbfp->fd, roff, (const struct iovec *)iov, iovc, 0);
}

merr_t
mblock_file_write(
    struct mblock_file *mbfp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
	off_t               off)
{
    uint64_t woff;
    merr_t   err;

    if (ev(!mbfp || !iov))
        return merr(EINVAL);

    /* TODO: Add offset and len validation */

    if (iovc == 0)
        return 0;

    err = mblock_file_find(mbfp, &mbid, 1);
    if (ev(err))
        return err;

    woff = block_off(mbid);
    woff += off;

    return mbfp->io->write(mbfp->fd, woff, (const struct iovec *)iov, iovc, 0);
}
