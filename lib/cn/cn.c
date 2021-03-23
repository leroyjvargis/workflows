/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_cn
#define MTF_MOCK_IMPL_cn_cursor
#define MTF_MOCK_IMPL_cn_mblocks
#define MTF_MOCK_IMPL_cn_comp
#define MTF_MOCK_IMPL_cn_internal

#include <hse_util/platform.h>
#include <hse_util/string.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/log2.h>
#include <hse_util/string.h>
#include <hse_util/xrand.h>
#include <hse_util/vlb.h>

#include <hse_util/perfc.h>

#include <hse/hse_limits.h>

#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/cn_cursor.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/cursor.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/cn_kvdb.h>
#include <hse_ikvdb/kvs_cparams.h>

#include <hse_ikvdb/csched.h>

#include <mpool/mpool.h>

#include "cn_internal.h"

#include "cn_work.h"
#include "cn_tree.h"
#include "cn_tree_cursor.h"
#include "cn_tree_create.h"
#include "cn_tree_compact.h"
#include "cn_tree_stats.h"
#include "cn_mblocks.h"

#include "omf.h"
#include "kvset.h"
#include "spill.h"
#include "blk_list.h"
#include "kv_iterator.h"
#include "vblock_reader.h"
#include "wbt_reader.h"
#include "intern_builder.h"
#include "bloom_reader.h"
#include "cn_perfc.h"
#include "pscan.h"

struct tbkt;
struct mclass_policy;

void
hse_log_reg_cn(void);

merr_t
cn_init(void)
{
    struct pscan *cur HSE_MAYBE_UNUSED;
    merr_t err;

    /* If you trip this assert then likely you ignored the warning in pscan.h
     * and you need to adjust cn_pscan_create() to accomodate your changes.
     */
    assert(offsetof(struct pscan, pt_buf) + sizeof(cur->pt_buf) == sizeof(*cur));

    err = wbti_init();
    if (err)
        return err;

    err = ib_init();
    if (err) {
        wbti_fini();
        return err;
    }

    err = cn_tree_init();
    if (err) {
        ib_fini();
        wbti_fini();
        return err;
    }

    kvset_init();
    hse_log_reg_cn();

    return 0;
}

void
cn_fini(void)
{
    kvset_fini();
    cn_tree_fini();
    ib_fini();
    wbti_fini();
}

u64
cn_get_ingest_dgen(const struct cn *cn)
{
    return atomic64_read(&cn->cn_ingest_dgen);
}

void
cn_inc_ingest_dgen(struct cn *cn)
{
    atomic64_inc(&cn->cn_ingest_dgen);
}

struct kvs_rparams *
cn_get_rp(const struct cn *cn)
{
    return cn->rp;
}

struct mclass_policy *
cn_get_mclass_policy(const struct cn *cn)
{
    return cn->cn_mpolicy;
}

bool
cn_is_closing(const struct cn *cn)
{
    return cn->cn_closing;
}

bool
cn_is_replay(const struct cn *cn)
{
    return cn->cn_replay;
}

struct mpool *
cn_get_dataset(const struct cn *cn)
{
    return cn->cn_dataset;
}

void *
cn_get_tree(const struct cn *handle)
{
    return handle->cn_tree;
}

u64
cn_get_seqno_horizon(struct cn *cn)
{
    return ikvdb_horizon(cn->ikvdb);
}

struct workqueue_struct *
cn_get_io_wq(struct cn *cn)
{
    return cn->cn_io_wq;
}

struct workqueue_struct *
cn_get_maint_wq(struct cn *cn)
{
    return cn->cn_maint_wq;
}

struct csched *
cn_get_sched(struct cn *cn)
{
    return cn->csched;
}

atomic_t *
cn_get_cancel(struct cn *cn)
{
    return &cn->cn_maint_cancel;
}

struct perfc_set *
cn_get_perfc(struct cn *cn, enum cn_action action)
{
    switch (action) {

        case CN_ACTION_COMPACT_K:
            return &cn->cn_pc_kcompact;

        case CN_ACTION_COMPACT_KV:
            return &cn->cn_pc_kvcompact;

        case CN_ACTION_SPILL:
            return &cn->cn_pc_spill;

        case CN_ACTION_NONE:
        case CN_ACTION_END:
            break;
    }

    return 0;
}

struct perfc_set *
cn_pc_capped_get(struct cn *cn)
{
    return &cn->cn_pc_capped;
}

struct perfc_set *
cn_pc_mclass_get(struct cn *cn)
{
    return &cn->cn_pc_mclass;
}

/**
 * cn_get_ref() - increment a cn reference counter
 *
 * cn reference counts are used to ensure cn, along with it's tree and nodes,
 * are not deleted while in use by another object.  There is no explicit tree
 * reference count since cn and cn_tree objects have the same lifecycle.
 * Objects that need a tree ref should use a cn ref.
 *
 * See docs/cn-reference-counting.md for more information.
 */
void
cn_ref_get(struct cn *cn)
{
    atomic_inc(&cn->cn_refcnt);
}

void
cn_ref_put(struct cn *cn)
{
    atomic_dec(&cn->cn_refcnt);
}

u64
cn_hash_get(const struct cn *cn)
{
    return cn->cn_hash;
}

u64
cn_get_cnid(const struct cn *handle)
{
    return handle->cn_cnid;
}

struct cndb *
cn_get_cndb(const struct cn *handle)
{
    return handle ? handle->cn_cndb : 0;
}

struct cn_kvdb *
cn_get_cn_kvdb(const struct cn *handle)
{
    return handle ? handle->cn_kvdb : 0;
}

u32
cn_get_flags(const struct cn *handle)
{
    return handle->cn_cflags;
}

struct perfc_set *
cn_get_ingest_perfc(const struct cn *cn)
{
    return cn ? &((struct cn *)cn)->cn_pc_ingest : 0;
}

u32
cn_cp2cflags(struct kvs_cparams *cp)
{
    u32 flags = 0;

    if (cp->cp_kvs_ext01)
        flags |= CN_CFLAG_CAPPED;

    return flags;
}

bool
cn_is_capped(const struct cn *cn)
{
    return cn->cn_cflags & CN_CFLAG_CAPPED;
}

void
cn_disable_maint(struct cn *cn, bool onoff)
{
    if (cn->rp->cn_maint_disable != onoff) {
        cn->rp->cn_maint_disable = onoff;

        hse_log(
            HSE_NOTICE "cn_disable_maint: %s: background compaction %s",
            cn->cn_kvsname,
            onoff ? "disabled" : "enabled");
    }
}

struct kvs_cparams *
cn_get_cparams(const struct cn *handle)
{
    return handle->cp;
}

size_t
cn_get_sfx_len(struct cn *cn)
{
    return cn->cp->cp_sfx_len;
}

/*----------------------------------------------------------------
 * CN GET
 */

merr_t
cn_get(
    struct cn *          cn,
    struct kvs_ktuple *  kt,
    u64                  seq,
    enum key_lookup_res *res,
    struct kvs_buf *     vbuf)
{
    struct query_ctx qctx;

    qctx.qtype = QUERY_GET;
    return cn_tree_lookup(cn->cn_tree, &cn->cn_pc_get, kt, seq, res, &qctx, 0, vbuf);
}

merr_t
cn_pfx_probe(
    struct cn *          cn,
    struct kvs_ktuple *  kt,
    u64                  seq,
    enum key_lookup_res *res,
    struct query_ctx *   qctx,
    struct kvs_buf *     kbuf,
    struct kvs_buf *     vbuf)
{
    return cn_tree_lookup(cn->cn_tree, &cn->cn_pc_get, kt, seq, res, qctx, kbuf, vbuf);
}

/**
 * cn_commit_blks() - commit a set of mblocks
 * @ds:           dataset
 * @blks:         array of kvset_mblock structs
 * @skip:         skip this number of mblocks at the beginning of blks, they
 *                are already committed.
 * @n_committed:  (output) number of successfully committed mblocks by this
 *                function call.
 *
 * Given @N mblock IDs, attempt to commit all @N mblocks.  If all commits are
 * successful, then set @n_committed to @N and return with success status.  If
 * the @i-th commit fails, then: do not attempt to commit any more of the @N
 * mblocks, set @n_committed to @i-%1, and return with an error status
 * indicating the underlying cause of failure.
 */
static merr_t
cn_commit_blks(struct mpool *ds, struct blk_list *blks, u32 skip, u32 *n_committed)
{
    merr_t err;
    u32    bx;

    for (bx = skip; bx < blks->n_blks; ++bx) {
        err = commit_mblock(ds, &blks->blks[bx]);
        if (ev(err))
            return err;
        *n_committed += 1;
    }
    return 0;
}

merr_t
cn_mblocks_commit(
    struct mpool *        ds,
    struct cndb *         cndb,
    u64                   cnid,
    u64                   txid,
    u32                   num_lists,
    struct kvset_mblocks *list,
    enum cn_mutation      mutation,
    u32 *                 vcommitted,
    u32 *                 n_committed,
    u64 *                 context,
    u64 *                 tags)
{
    merr_t err = 0;
    u32    lx;

    *n_committed = 0;

    /* [HSE_REVISIT] it is possible to have no blocks here, but we must emit
     * a C record so that the metadata is complete.  In that case, there
     * will be no corresponding meta record, but the replay algorithm can
     * easily anticipate this case.
     */
    for (lx = 0; lx < num_lists; lx++) {

        /*
         * If key compaction, all the vblocks are already committed
         * and all of them need to be kept on rollback.
         * Else if vcommmited is NULL all the vblocks need to be
         * committed and none will be kept on rollback.
         * Else the number of vblocks already committed and to keep
         * on rollback is vcommitted[lx].
         */
        err = cndb_txn_txc(
            cndb,
            txid,
            cnid,
            context,
            &list[lx],
            (mutation == CN_MUT_KCOMPACT) ? list[lx].vblks.n_blks
                                          : vcommitted ? vcommitted[lx] : 0);
        if (ev(err))
            return err;
        tags[lx] = *context;
    }

    for (lx = 0; lx < num_lists; lx++) {
        err = cn_commit_blks(ds, &list[lx].kblks, 0, n_committed);
        if (ev(err))
            return err;

        if (mutation == CN_MUT_KCOMPACT)
            continue;

        err = cn_commit_blks(ds, &list[lx].vblks, vcommitted ? vcommitted[lx] : 0, n_committed);
        if (ev(err))
            return err;
    }

    return 0;
}

/**
 * cn_delete_blks() - delete or abort multiple mblocks
 * @ds:           dataset
 * @blks:         blk_list of mblocks to delete
 * @n_committed:  number of mblocks in list already committed
 *
 * Given a blk_list of mblocks, delete the first @n_committed and
 * abort the remaining N-@n_committed.
 */
static void
cn_delete_blks(struct mpool *ds, struct blk_list *blks, u32 n_committed)
{
    u32 bx;

    for (bx = 0; bx < blks->n_blks; ++bx) {
        if (n_committed > 0) {
            delete_mblock(ds, &blks->blks[bx]);
            n_committed -= 1;
        } else {
            abort_mblock(ds, &blks->blks[bx]);
        }
    }
}

void
cn_mblocks_destroy(
    struct mpool *        ds,
    u32                   num_lists,
    struct kvset_mblocks *list,
    bool                  kcompact,
    u32                   n_committed)
{
    u32 lx;

    for (lx = 0; lx < num_lists; lx++) {
        cn_delete_blks(ds, &list[lx].kblks, n_committed);
        if (kcompact)
            continue;
        cn_delete_blks(ds, &list[lx].vblks, n_committed);
    }
}

static inline size_t
roundup_size(size_t val, size_t align)
{
    return align * ((val + align - 1) / align);
}

/**
 * cn_mb_est_alen() - estimate media space required to store data in mblocks
 * @full_captgt: value of mbc_captgt in mpool_mblock_alloc() for full size
 *               mblock
 * @alloc_unit: mblock unit of allocation (MPOOL_DEV_VEBLOCKBY_DEFAULT)
 * @wlen: total wlen needed by caller
 * @flags: see CN_MB_FLAGS_*
 *
 * This function is used to estimate the total media capacity used by
 * kblocks and vblocks after a compaction operation.  For example, if
 * a node contains 1.5 GiB of key data, 15 GiB of value data, and has
 * space amp of 1.5, then the expected key and value data after
 * compaction is 1.0 and 10.0 GiB respectively.  In that case, this
 * function would be called twice (once for kblocks and once for
 * vblocks) as follows:
 *
 * For kblocks (which are not preallocated):
 *    @full_captgt = KBLOCK_MAX_SIZE
 *    @alloc_unit = MPOOL_DEV_VEBLOCKBY_DEFAULT
 *    @wlen = 1.0 GiB
 *    @flags = CN_MB_EST_FLAGS_POW2;
 *
 * For vblocks (which are preallocated):
 *    @full_captgt = VBLOCK_MAX_SIZE
 *    @alloc_unit = MPOOL_DEV_VEBLOCKBY_DEFAULT
 *    @wlen  = 10.0 GiB
 *    @flags = CN_MB_EST_FLAGS_PREALLOC;
 */
/* MTF_MOCK */
size_t
cn_mb_est_alen(size_t full_captgt, size_t mb_alloc_unit, size_t wlen, uint flags)
{
    size_t full_alen; /* allocated len of one full mblock */
    size_t alen;      /* sum allocated len for all mblocks */
    size_t extra;
    bool   prealloc;
    bool   truncate;
    bool   pow2;

    if (!full_captgt || !mb_alloc_unit || !wlen)
        return 0;

    /* Storing wlen bytes in a set of mblocks requires a set of full
     * mblocks and at most one partial mblock.  The capacity of
     * each full mblock (full_alen) is determined by 'full_captgt'
     * rounded up to the nearest mblock allocation unit.  If
     * mblocks are preallocated and truncation is disabled, then
     * the partial mblock will be full size, otherwise it will be
     * rounded up to the mblock allocation unit.
     */

    prealloc = flags & CN_MB_EST_FLAGS_PREALLOC;
    truncate = flags & CN_MB_EST_FLAGS_TRUNCATE;
    pow2 = flags & CN_MB_EST_FLAGS_POW2;

    if (pow2)
        full_captgt = roundup_pow_of_two(full_captgt);

    full_alen = roundup_size(full_captgt, mb_alloc_unit);
    alen = full_alen * (wlen / full_alen);
    extra = wlen - alen;

    if (extra) {
        if (prealloc && !truncate)
            extra = full_alen;
        else if (pow2)
            extra = roundup_pow_of_two(extra);

        alen += roundup_size(extra, mb_alloc_unit);
    }

    return alen;
}

/**
 * cn_ingest_prep()
 * @cn:
 * @childv:
 * @childc:
 * @txid:
 * @context:
 * @vcommitted: vblocks already committed.
 *      Can be NULL. If NULL, none of the vblocks are already committed.
 * @le_out:
 */
static merr_t
cn_ingest_prep(
    struct cn *           cn,
    struct kvset_mblocks *childv,
    unsigned int          childc,
    u64                   txid,
    u64 *                 context,
    u32 *                 vcommitted,
    struct kvset **       kvsetp)
{
    struct kvset_meta km = {};
    struct kvset *    kvset;
    u64               dgen, tag_throwaway = 0;
    u32               commitc = 0;
    merr_t            err = 0;

    /* Currently support only one child (this would need
     * to change if we re-enable c0_spill).
     */
    if (!childv || childc != 1)
        return merr(ev(EINVAL));

    dgen = atomic64_read(&cn->cn_ingest_dgen) + 1;

    /* Note: cn_mblocks_commit() creates "C" records in CNDB */
    err = cn_mblocks_commit(
        cn->cn_dataset,
        cn->cn_cndb,
        cn->cn_cnid,
        txid,
        childc,
        childv,
        CN_MUT_INGEST,
        vcommitted,
        &commitc,
        context,
        &tag_throwaway);
    if (ev(err))
        goto done;

    /* Lend childv[0] kblk and vblk lists to kvset_create().
     * Yes, the struct copy is a bit gross, but it works and
     * avoids unnecessary allocations of temporary lists.
     */
    km.km_kblk_list = childv[0].kblks;
    km.km_vblk_list = childv[0].vblks;
    km.km_dgen = dgen;
    km.km_node_level = 0;
    km.km_node_offset = 0;

    km.km_vused = childv[0].bl_vused;
    km.km_compc = 0;
    km.km_capped = cn_is_capped(cn);
    km.km_restored = false;
    km.km_scatter = km.km_vused ? 1 : 0;

    /* It is conceivable that there are no kblocks on ingest.  All it takes
     * is the creation of builder in the c0 ingest code without any keys
     * ever making it to that builder.  We've already told CNDB how many
     * C-records to expect, so we had to get this far to create the
     * correct number of C and CMeta records.  But if there are in fact
     * no kblocks, there's nothing more to do.  CNDB recognizes this
     * and realizes that this is not a real kvset.
     */
    if (childv[0].kblks.n_blks == 0) {
        assert(childv[0].vblks.n_blks == 0);
        goto done;
    }

    /* DO NOT LOG META WHEN childv[0].kblks.n_blks == 0 */
    err = cndb_txn_meta(cn->cn_cndb, txid, cn->cn_cnid, *context, &km);
    if (ev(err))
        goto done;

    err = kvset_create(cn->cn_tree, *context, &km, &kvset);
    if (ev(err))
        goto done;

    *kvsetp = kvset;

done:
    if (err) {
        /* Delete committed mblocks, abort those not yet committed. */
        cn_mblocks_destroy(cn->cn_dataset, childc, childv, 0, commitc);
        *kvsetp = NULL;
    }

    return err;
}

merr_t
cn_ingestv(
    struct cn **           cn,
    struct kvset_mblocks **mbv,
    int *                  mbc,
    u32 *                  vcommitted,
    u64                    ingestid,
    int                    ingestc,
    bool *                 ingested_out,
    u64 *                  seqno_max_out)
{
    struct kvset **    kvsetv = NULL;
    struct cndb *      cndb = NULL;
    struct kvset_stats kst = {};

    merr_t err = 0;
    u64    txid = 0;
    uint   i, first, last, count, check;
    u64    context = 0; /* must be initialized to zero */
    u64    seqno_max = 0, seqno_min = U64_MAX;
    uint   ext_vblk_count = 0;
    bool   log_ingest = false;
    u64    dgen = 0;

    /* Ingestc can be large (256), and is typically sparse.
     * Remember the first and last index so we don't have
     * to iterate the entire list each time.
     */
    first = last = count = 0;
    for (i = 0; i < ingestc; i++) {

        if (!cn[i] || !mbc[i] || !mbv[i])
            continue;

        seqno_max = max_t(u64, seqno_max, mbv[i]->bl_seqno_max);
        seqno_min = min_t(u64, seqno_min, mbv[i]->bl_seqno_min);

        if (ev(seqno_min > seqno_max)) {
            err = merr(EINVAL);
            goto done;
        }

        cndb = cn[i]->cn_cndb;

        if (!count)
            first = i;
        last = i;
        count++;
        perfc_inc(&cn[i]->cn_pc_ingest, PERFC_BA_CNCOMP_START);
    }

    if (!count) {
        *ingested_out = false;
        *seqno_max_out = seqno_max;
        err = 0;
        goto done;
    }

    kvsetv = calloc(ingestc, sizeof(*kvsetv));
    if (ev(!kvsetv)) {
        err = merr(EINVAL);
        goto done;
    }

    err = cndb_txn_start(cndb, &txid, ingestid, count, 0, seqno_max);
    if (ev(err))
        goto done;

    check = 0;
    for (i = first; i <= last; i++) {
        u32 *vcp;

        if (!cn[i] || !mbc[i] || !mbv[i])
            continue;

        if (cn[i]->rp && !log_ingest)
            log_ingest = cn[i]->rp->cn_compaction_debug & 2;

        vcp = (ingestid == CNDB_INVAL_INGESTID) ? NULL : &vcommitted[i];
        if (vcp)
            ext_vblk_count += *vcp;

        err = cn_ingest_prep(cn[i], mbv[i], mbc[i], txid, &context, vcp, &kvsetv[i]);
        if (ev(err))
            goto done;
        check++;
    }
    assert(check == count);

    /* There must not be any failure conditions after successful ACK_C
     * because the operation has been committed.
     */
    err = cndb_txn_ack_c(cndb, txid);
    if (ev(err))
        goto done;

    check = 0;
    for (i = first; i <= last; i++) {

        if (!cn[i] || !mbc[i] || !mbv[i])
            continue;

        if (log_ingest) {
            kvset_stats_add(kvset_statsp(kvsetv[i]), &kst);
            dgen = kvsetv[i]->ks_dgen;
        }

        cn_tree_ingest_update(
            cn[i]->cn_tree,
            kvsetv[i],
            mbv[i]->bl_last_ptomb,
            mbv[i]->bl_last_ptlen,
            mbv[i]->bl_last_ptseq);
        check++;
    }
    assert(check == count);

    *ingested_out = true;
    *seqno_max_out = seqno_max;

    if (log_ingest) {
        hse_slog(
            HSE_NOTICE,
            HSE_SLOG_START("cn_ingest"),
            HSE_SLOG_FIELD("dgen", "%lu", (ulong)dgen),
            HSE_SLOG_FIELD("seqno", "%lu", (ulong)ingestid),
            HSE_SLOG_FIELD("kvsets", "%lu", (ulong)kst.kst_kvsets),
            HSE_SLOG_FIELD("keys", "%lu", (ulong)kst.kst_keys),
            HSE_SLOG_FIELD("kblks", "%lu", (ulong)kst.kst_kblks),
            HSE_SLOG_FIELD("vblks_int", "%lu", (ulong)kst.kst_vblks - ext_vblk_count),
            HSE_SLOG_FIELD("vblks_ext", "%lu", (ulong)ext_vblk_count),
            HSE_SLOG_FIELD("kalen", "%lu", (ulong)kst.kst_kalen),
            HSE_SLOG_FIELD("kwlen", "%lu", (ulong)kst.kst_kwlen),
            HSE_SLOG_FIELD("valen", "%lu", (ulong)kst.kst_valen),
            HSE_SLOG_FIELD("vwlen", "%lu", (ulong)kst.kst_vwlen),
            HSE_SLOG_FIELD("vulen", "%lu", (ulong)kst.kst_vulen),
            HSE_SLOG_END);
    }

done:
    if (err && txid && cndb_txn_nak(cndb, txid))
        ev(1);

    /* NOTE: we always free the callers kvset mblocks */
    for (i = first; i <= last; i++) {
        kvset_mblocks_destroy(mbv[i]);

        if (cn[i])
            perfc_inc(&cn[i]->cn_pc_ingest, PERFC_BA_CNCOMP_FINISH);
    }

    free(kvsetv);

    return err;
}

static void
cn_maintenance_task(struct work_struct *context)
{
    struct cn *cn;

    cn = container_of(context, struct cn, cn_maintenance_work);

    assert(cn->cn_kvdb_health);
    assert(cn_is_capped(cn));

    while (!cn->cn_maintenance_stop) {

        if (kvdb_health_check(cn->cn_kvdb_health, KVDB_HEALTH_FLAG_ALL))
            cn->rp->cn_maint_disable = true;

        if (!cn->rp->cn_maint_disable)
            cn_tree_capped_compact(cn->cn_tree);

        usleep(USEC_PER_SEC);
    }
}

struct cn_tstate_impl {
    struct cn_tstate     tsi_tstate;
    struct cn *          tsi_cn;
    struct mutex         tsi_lock;
    struct cn_tstate_omf tsi_omf;
};

static void
cn_tstate_get(struct cn_tstate *tstate, u32 *genp, u8 *mapv)
{
    struct cn_tstate_impl *impl;

    assert(tstate && genp && mapv);

    impl = container_of(tstate, struct cn_tstate_impl, tsi_tstate);

    mutex_lock(&impl->tsi_lock);
    *genp = omf_ts_khm_gen(&impl->tsi_omf);
    omf_ts_khm_mapv(&impl->tsi_omf, mapv, CN_TSTATE_KHM_SZ);
    mutex_unlock(&impl->tsi_lock);
}

static merr_t
cn_tstate_update(
    struct cn_tstate *   tstate,
    cn_tstate_prepare_t *ts_prepare,
    cn_tstate_commit_t * ts_commit,
    cn_tstate_abort_t *  ts_abort,
    void *               arg)
{
    struct cn_tstate_impl *impl;
    struct cn_tstate_omf * omf;
    struct cn *            cn;
    merr_t                 err;

    if (!tstate)
        return 0;

    if (ev(!ts_prepare || !ts_commit || !ts_abort))
        return merr(EINVAL);

    impl = container_of(tstate, struct cn_tstate_impl, tsi_tstate);
    omf = &impl->tsi_omf;

    cn = impl->tsi_cn;
    assert(cn);

    mutex_lock(&impl->tsi_lock);
    err = ts_prepare(omf, arg);
    if (!err) {
        err = cndb_cn_blob_set(cn->cn_cndb, cn->cn_cnid, sizeof(*omf), omf);

        if (err)
            ts_abort(omf, arg);
        else
            ts_commit(omf, arg);
    }
    mutex_unlock(&impl->tsi_lock);

    return err;
}

static merr_t
cn_tstate_create(struct cn *cn)
{
    const char *           errmsg = "";
    struct cn_tstate_impl *impl;
    struct cn_tstate_omf * omf;
    merr_t                 err;
    void *                 ptr;
    size_t                 sz;

    impl = alloc_aligned(sizeof(*impl), __alignof(*impl));
    if (ev(!impl))
        return merr(ENOMEM);

    memset(impl, 0, sizeof(*impl));
    mutex_init(&impl->tsi_lock);
    impl->tsi_tstate.ts_update = cn_tstate_update;
    impl->tsi_tstate.ts_get = cn_tstate_get;
    impl->tsi_cn = cn;

    omf = &impl->tsi_omf;
    ptr = NULL;
    sz = 0;

    err = cndb_cn_blob_get(cn->cn_cndb, cn->cn_cnid, &sz, &ptr);
    if (ev(err)) {
        errmsg = "unable to load cn_tstate";
        goto errout;
    }

    if (!ptr && sz == 0) {
        omf_set_ts_magic(omf, CN_TSTATE_MAGIC);
        omf_set_ts_version(omf, CN_TSTATE_VERSION);

        if (!ikvdb_rdonly(cn->ikvdb)) {
            err = cndb_cn_blob_set(cn->cn_cndb, cn->cn_cnid, sizeof(*omf), omf);
            if (ev(err)) {
                errmsg = "unable to store initial cn_tstate";
                goto errout;
            }
        }
    } else {
        if (ev(!ptr || sz != sizeof(*omf))) {
            errmsg = "invalid cn_tstate size";
            err = merr(EINVAL);
            goto errout;
        }

        memcpy(omf, ptr, sz);
    }

    if (ev(omf_ts_magic(omf) != CN_TSTATE_MAGIC)) {
        errmsg = "invalid cn_tstate magic";
        err = merr(EINVAL);
        goto errout;
    } else if (ev(omf_ts_version(omf) != CN_TSTATE_VERSION)) {
        errmsg = "invalid cn_tstate version";
        err = merr(EINVAL);
        goto errout;
    }

    cn->cn_tstate = &impl->tsi_tstate;

errout:
    if (err) {
        hse_elog(HSE_ERR "%s: %s: @@e", err, __func__, errmsg);
        mutex_destroy(&impl->tsi_lock);
        free_aligned(impl);
    }

    free(ptr);

    return err;
}

static void
cn_tstate_destroy(struct cn_tstate *tstate)
{
    struct cn_tstate_impl *impl;

    if (ev(!tstate))
        return;

    impl = container_of(tstate, struct cn_tstate_impl, tsi_tstate);

    assert(impl->tsi_cn);
    impl->tsi_cn = NULL;

    mutex_destroy(&impl->tsi_lock);
    free_aligned(impl);
}

struct cn_kvsetmk_ctx {
    struct cn *ckmk_cn;
    u64 *      ckmk_dgen;
    uint       ckmk_node_level_max;
    uint       ckmk_kvsets;
};

static merr_t
cn_kvset_mk(struct cn_kvsetmk_ctx *ctx, struct kvset_meta *km, u64 tag)
{
    struct kvset *kvset;
    struct cn *   cn = ctx->ckmk_cn;
    merr_t        err;

    err = kvset_create(cn->cn_tree, tag, km, &kvset);
    if (ev(err))
        return err;

    err = cn_tree_insert_kvset(cn->cn_tree, kvset, km->km_node_level, km->km_node_offset);
    if (ev(err)) {
        kvset_put_ref(kvset);
        return err;
    }

    ctx->ckmk_kvsets++;

    if (km->km_dgen > *(ctx->ckmk_dgen))
        *(ctx->ckmk_dgen) = km->km_dgen;

    if (km->km_node_level > ctx->ckmk_node_level_max)
        ctx->ckmk_node_level_max = km->km_node_level;

    return 0;
}

/*----------------------------------------------------------------
 * SECTION: perf counter initialization
 *
 * See kvs_perfc_fini() in kvs.c.
 */

static void
cn_perfc_alloc(struct cn *cn)
{
    int  i, warn;
    char name_buf[DT_PATH_COMP_ELEMENT_LEN];

    struct {
        struct perfc_name *schema;
        uint               schema_len;
        char *             instance_name;
        struct perfc_set * instance;
    } pc_sets[] = {
        { cn_perfc_get, PERFC_EN_CNGET, "cnget", &cn->cn_pc_get },

        { cn_perfc_compact, PERFC_EN_CNCOMP, "ingest", &cn->cn_pc_ingest },

        { cn_perfc_compact, PERFC_EN_CNCOMP, "spill", &cn->cn_pc_spill },

        { cn_perfc_compact, PERFC_EN_CNCOMP, "kcompact", &cn->cn_pc_kcompact },

        { cn_perfc_compact, PERFC_EN_CNCOMP, "kvcompact", &cn->cn_pc_kvcompact },

        { cn_perfc_shape, PERFC_EN_CNSHAPE, "rnode", &cn->cn_pc_shape_rnode },

        { cn_perfc_shape, PERFC_EN_CNSHAPE, "inode", &cn->cn_pc_shape_inode },

        { cn_perfc_shape, PERFC_EN_CNSHAPE, "lnode", &cn->cn_pc_shape_lnode },

        { cn_perfc_capped, PERFC_EN_CNCAPPED, "capped", &cn->cn_pc_capped },

        { cn_perfc_mclass, PERFC_EN_CNMCLASS, "mclass", &cn->cn_pc_mclass },
    };

    i = snprintf(
        name_buf, sizeof(name_buf), "%s%s%s", cn->cn_mpname, IKVDB_SUB_NAME_SEP, cn->cn_kvsname);

    if (i >= sizeof(name_buf)) {
        hse_log(HSE_WARNING "cn perfc name buffer too small");
        return;
    }

    /* Not considered fatal if perfc fails */
    warn = 0;
    for (i = 0; i < NELEM(pc_sets); i++) {

        if (perfc_ctrseti_alloc(
                COMPNAME,
                name_buf,
                pc_sets[i].schema,
                pc_sets[i].schema_len,
                pc_sets[i].instance_name,
                pc_sets[i].instance)) {

            warn++;
        }
    }

    if (warn)
        hse_log(HSE_WARNING "Failed %d of %lu cn perf counter sets", warn, NELEM(pc_sets));
}

/**
 * cn_perfc_free() - Free the perfc counter sets handles.
 * @cn:
 */
static void
cn_perfc_free(struct cn *cn)
{
    perfc_ctrseti_free(&cn->cn_pc_get);
    perfc_ctrseti_free(&cn->cn_pc_ingest);
    perfc_ctrseti_free(&cn->cn_pc_spill);
    perfc_ctrseti_free(&cn->cn_pc_kcompact);
    perfc_ctrseti_free(&cn->cn_pc_kvcompact);
    perfc_ctrseti_free(&cn->cn_pc_shape_rnode);
    perfc_ctrseti_free(&cn->cn_pc_shape_inode);
    perfc_ctrseti_free(&cn->cn_pc_shape_lnode);
    perfc_ctrseti_free(&cn->cn_pc_capped);
    perfc_ctrseti_free(&cn->cn_pc_mclass);
}

/*----------------------------------------------------------------
 * SECTION: open/close
 */

merr_t
cn_open(
    struct cn_kvdb *    cn_kvdb,
    struct mpool *      ds,
    struct kvdb_kvs *   kvs,
    struct cndb *       cndb,
    u64                 cnid,
    struct kvs_rparams *rp,
    const char *        mp_name,
    const char *        kvs_name,
    struct kvdb_health *health,
    uint                flags,
    struct cn **        cn_out)
{
    ulong       ksz, kcnt, kshift, vsz, vcnt, vshift;
    ulong       mavail;
    const char *kszsuf, *vszsuf;
    merr_t      err;
    struct cn * cn;
    size_t      sz;
    u64         dgen = 0;
    bool        maint;
    uint64_t    mperr, staging_absent;

    struct cn_kvsetmk_ctx ctx = { 0 };
    struct mpool_params   mpool_params;
    struct merr_info      ei;

    assert(ds);
    assert(kvs);
    assert(cndb);
    assert(mp_name);
    assert(kvs_name);
    assert(health);
    assert(cn_out);

    mperr = mpool_params_get(ds, &mpool_params, NULL);
    if (mperr) {
        hse_log(HSE_ERR "mpool_params_get error %s\n", merr_info(mperr, &ei));
        return merr_errno(mperr);
    }

    /* stash rparams behind cn if caller did not provide them */
    sz = sizeof(*cn);
    if (!rp)
        sz += sizeof(*rp);

    cn = alloc_aligned(sz, __alignof(*cn));
    if (ev(!cn))
        return merr(ENOMEM);

    memset(cn, 0, sz);

    if (!rp) {
        rp = (void *)(cn + 1);
        *rp = kvs_rparams_defaults();
    }

    strlcpy(cn->cn_mpname, mp_name, sizeof(cn->cn_mpname));
    strlcpy(cn->cn_kvsname, kvs_name, sizeof(cn->cn_kvsname));

    cn->cn_kvdb = cn_kvdb;
    cn->rp = rp;
    cn->cp = kvdb_kvs_cparams(kvs);
    cn->cn_cndb = cndb;
    cn->ikvdb = ikvdb_kvdb_handle(kvdb_kvs_parent(kvs));
    cn->cn_dataset = ds;
    cn->cn_cnid = cnid;
    cn->cn_cflags = kvdb_kvs_flags(kvs);
    cn->cn_kvdb_health = health;
    cn->cn_hash = key_hash64(kvs_name, strlen(kvs_name));
    cn->cn_mpool_params = mpool_params;

    hse_meminfo(NULL, &mavail, 30);

    staging_absent = mpool_mclass_get(ds, MP_MED_STAGING, NULL);
    if (staging_absent) {
        if (strcmp(rp->mclass_policy, "capacity_only")) {
            hse_log(
                HSE_WARNING
                "Staging media is not configured. Switching to capacity_only media class policy.");
            strlcpy(rp->mclass_policy, "capacity_only", HSE_MPOLICY_NAME_LEN_MAX);
        }
    }

    /* Reduce c1 vbuilder contribution for low memory configurations. */
    if (mavail < 128)
        rp->c1_vblock_cap = 4;

    /* If this cn is capped disable c1 vbuilder to be space efficient.
     */
    if (cn_is_capped(cn)) {
        rp->kvs_cursor_ttl = rp->cn_capped_ttl;
        rp->c1_vblock_cap = 0;
    }

    /* Enable tree maintenance if we have a scheduler,
     * and if replay, diag and rdonly are all false.
     */
    cn->csched = ikvdb_get_csched(cn->ikvdb);

    cn->cn_mpolicy = ikvdb_get_mclass_policy(cn->ikvdb, rp->mclass_policy);
    hse_log(HSE_NOTICE "%s is using %s media class policy", cn->cn_kvsname, rp->mclass_policy);
    if (ev(!cn->cn_mpolicy)) {
        err = merr(EINVAL);
        hse_log(HSE_ERR "%s Invalid media class policy.", cn->cn_kvsname);
        goto err_exit;
    }

    cn->cn_replay = flags & IKVS_OFLAG_REPLAY;
    maint = cn->csched && !cn->cn_replay && !rp->cn_diag_mode && !rp->rdonly;

    /* no perf counters in replay mode */
    if (!cn->cn_replay)
        cn_perfc_alloc(cn);

    err = cn_tstate_create(cn);
    if (ev(err))
        goto err_exit;

    err = cn_tree_create(&cn->cn_tree, cn->cn_tstate, cn->cn_cflags, cn->cp, health, rp);
    if (ev(err))
        goto err_exit;

    cn_tree_setup(cn->cn_tree, ds, cn, rp, cndb, cnid, cn->cn_kvdb);

    ctx.ckmk_cn = cn;
    ctx.ckmk_dgen = &dgen;

    ksz = kcnt = kshift = 0;
    vsz = vcnt = vshift = 0;
    kszsuf = vszsuf = "bkmgtp";

    if (cn_kvdb) {
        ksz = atomic64_read(&cn_kvdb->cnd_kblk_size);
        kcnt = atomic64_read(&cn_kvdb->cnd_kblk_cnt);
        vsz = atomic64_read(&cn_kvdb->cnd_vblk_size);
        vcnt = atomic64_read(&cn_kvdb->cnd_vblk_cnt);
    }

    err = cndb_cn_instantiate(cndb, cnid, &ctx, (void *)cn_kvset_mk);
    if (ev(err))
        goto err_exit;

    if (cn_kvdb) {
        /* [HSE_REVISIT]: This approach is not thread-safe */
        ksz = atomic64_read(&cn_kvdb->cnd_kblk_size) - ksz;
        kcnt = atomic64_read(&cn_kvdb->cnd_kblk_cnt) - kcnt;
        vsz = atomic64_read(&cn_kvdb->cnd_vblk_size) - vsz;
        vcnt = atomic64_read(&cn_kvdb->cnd_vblk_cnt) - vcnt;

        kshift = ilog2(ksz | 1) / 10;
        vshift = ilog2(vsz | 1) / 10;

        kszsuf += kshift;
        vszsuf += vshift;
    }

    cn_tree_set_initial_dgen(cn->cn_tree, dgen);

    cn_tree_samp_init(cn->cn_tree);

    atomic64_set(&cn->cn_ingest_dgen, cn_tree_initial_dgen(cn->cn_tree));

    hse_log(
        HSE_NOTICE "cn_open %s/%s replay %d fanout %u "
                   "pfx_len %u pfx_pivot %u cnid %lu depth %u/%u %s "
                   "kb %lu%c/%lu vb %lu%c/%lu",
        cn->cn_mpname,
        cn->cn_kvsname,
        cn->cn_replay,
        cn->cp->cp_fanout,
        cn->cp->cp_pfx_len,
        cn->cp->cp_pfx_pivot,
        (ulong)cnid,
        ctx.ckmk_node_level_max,
        cn_tree_max_depth(ilog2(cn->cp->cp_fanout)),
        cn_is_capped(cn) ? "capped" : "!capped",
        ksz >> (kshift * 10),
        *kszsuf,
        kcnt,
        vsz >> (vshift * 10),
        *vszsuf,
        vcnt);

    if (!maint)
        goto done;

    /* [HSE_REVISIT]: move the io_wq to csched so we have one set of
     * shared io workers per kvdb instead of one set per cn tree.
     */
    cn->cn_io_wq = alloc_workqueue("cn_io", 0, cn->rp->cn_io_threads ?: 4);
    if (!cn->cn_io_wq) {
        err = merr(ev(ENOMEM));
        goto err_exit;
    }

    /* Work queue for other work such as managing "capped" trees,
     * offloading kvset destroy from client queries, and running
     * vblock readahead operations.
     */
    cn->cn_maint_wq = alloc_workqueue("cn_maint", 0, 32);
    if (ev(!cn->cn_maint_wq)) {
        err = merr(ENOMEM);
        goto err_exit;
    }

    if (cn->csched && !cn_is_capped(cn))
        csched_tree_add(cn->csched, cn->cn_tree);

    if (cn_is_capped(cn)) {
        INIT_WORK(&cn->cn_maintenance_work, cn_maintenance_task);
        queue_work(cn->cn_maint_wq, &cn->cn_maintenance_work);
    }

    /* If capped bloom probability is zero then disable bloom creation.
     * Otherwise, cn_bloom_capped overrides cn_bloom_prob.
     */
    if (cn_is_capped(cn) && rp->cn_bloom_create) {
        rp->cn_bloom_create = (rp->cn_bloom_capped > 0);
        if (rp->cn_bloom_create)
            rp->cn_bloom_prob = rp->cn_bloom_capped;
    }

done:
    /* successful exit */
    cndb_getref(cndb);
    *cn_out = cn;

    return 0;

err_exit:
    destroy_workqueue(cn->cn_maint_wq);
    destroy_workqueue(cn->cn_io_wq);
    cn_tree_destroy(cn->cn_tree);
    cn_tstate_destroy(cn->cn_tstate);
    if (!cn->cn_replay)
        cn_perfc_free(cn);
    free_aligned(cn);

    return err ?: merr(ev(EBUG));
}

merr_t
cn_close(struct cn *cn)
{
    u64   report_ns = 5 * NSEC_PER_SEC;
    void *maint_wq = cn->cn_maint_wq;
    void *io_wq = cn->cn_io_wq;
    u64   next_report;
    useconds_t dlymax, dly;
    bool  cancel;

    cn->cn_maintenance_stop = true;
    cn->cn_closing = true;

    cancel = !cn->rp->cn_close_wait;
    if (cancel)
        atomic_set(&cn->cn_maint_cancel, 1);

    /* Wait for the cn maint thread to exit.  Any async kvset destroys
     * that may have started will be waited on by the cn_refcnt loop.
     */
    flush_workqueue(maint_wq);

    if (cn->csched && !cn->cn_replay)
        csched_tree_remove(cn->csched, cn->cn_tree, cancel);

    /* Wait for all compaction jobs and async kvset destroys to complete.
     * This wait holds up ikvdb_close(), so it's important not to dawdle.
     */
    next_report = get_time_ns() + NSEC_PER_SEC;
    dlymax = 1000;
    dly = 0;

    while (atomic_read(&cn->cn_refcnt) > 0) {
        if (dly < dlymax)
            dly += 100;
        usleep(dly);

        if (get_time_ns() < next_report)
            continue;

        hse_log(
            HSE_NOTICE "%s: cn %s waiting for %d async jobs...",
            __func__,
            cn->cn_kvsname,
            atomic_read(&cn->cn_refcnt));

        next_report = get_time_ns() + report_ns;
        dlymax = 10000;
    }

    /* The maint and I/O workqueues should be idle at this point...
     */
    flush_workqueue(maint_wq);
    flush_workqueue(io_wq);
    cn->cn_maint_wq = NULL;
    cn->cn_io_wq = NULL;

    cndb_cn_close(cn->cn_cndb, cn->cn_cnid);
    cndb_putref(cn->cn_cndb);

    cn_tree_destroy(cn->cn_tree);
    cn_tstate_destroy(cn->cn_tstate);

    destroy_workqueue(maint_wq);
    destroy_workqueue(io_wq);
    cn_perfc_free(cn);

    free_aligned(cn);

    return 0;
}

void
cn_periodic(struct cn *cn, u64 now)
{
    if (!PERFC_ISON(&cn->cn_pc_shape_rnode))
        return;

    now /= NSEC_PER_SEC;
    if (now >= cn->cn_pc_shape_next) {

        cn_tree_perfc_shape_report(
            cn->cn_tree, &cn->cn_pc_shape_rnode, &cn->cn_pc_shape_inode, &cn->cn_pc_shape_lnode);

        cn->cn_pc_shape_next = now + 60;
    }
}

void
cn_work_wrapper(struct work_struct *context)
{
    struct cn_work *work = container_of(context, struct cn_work, cnw_work);
    struct cn *     cn = work->cnw_cnref;

    work->cnw_handler(work);
    cn_ref_put(cn);
}

void
cn_work_submit(struct cn *cn, cn_work_fn *handler, struct cn_work *work)
{
    cn_ref_get(cn);

    work->cnw_cnref = cn;
    work->cnw_handler = handler;

    INIT_WORK(&work->cnw_work, cn_work_wrapper);
    queue_work(cn->cn_maint_wq, &work->cnw_work);
}

/**
 * cn_pscan_create() - allocate and initialize a pscan object
 */
static struct pscan *
cn_pscan_create(void)
{
    struct pscan *cur;
    size_t align, bufsz;
    void *mem;

    align = (__alignof(*cur) > SMP_CACHE_BYTES) ? __alignof(*cur) : SMP_CACHE_BYTES;
    bufsz = HSE_KVS_KLEN_MAX + HSE_KVS_VLEN_MAX;

    mem = vlb_alloc(sizeof(*cur) + bufsz + align * 16);
    if (ev(!mem))
        return NULL;

    /* Mitigate cacheline aliasing by offsetting from mem by a random
     * number of cache lines (because vlb_alloc() always returns a
     * page-aligned buffer).
     */
    cur = mem + align * (xrand64_tls() % 16);

    /* Initialize all fields up to but not including pt_buf[].
     */
    memset(cur, 0, offsetof(struct pscan, pt_buf));
    cur->bufsz = bufsz;
    cur->base = mem;

    return cur;
}

static void
cn_pscan_free(struct pscan *cur)
{
    size_t used = (cur->buf - cur->base) + cur->bufsz;

    /* [HSE_REVISIT] Track how much of cur->buf[] we used and pass the correct
     * size used to vlb_free() (typically it's less than a page size).  Until
     * then, we subtract a page size from the used size in order to avoid an
     * munmap() call of one page in vlb_free().
     */
    assert(used < VLB_KEEPSZ_MAX + PAGE_SIZE &&
           VLB_KEEPSZ_MAX + PAGE_SIZE < VLB_ALLOCSZ_MAX);

    vlb_free(cur->base, used - PAGE_SIZE);
}

/*
 * This cursor supports both prefix scans and full tree scans.
 *
 * There is an important caveat for full scans: if the CN tree
 * is large, there will be many, many kvsets that must be merged.
 * This implies significant resource load, and reduced performance.
 * Care must be taken when initiating a full scan.
 *
 * Prefix scans have a limited number of nodes to visit, and
 * therefore a limited number of kvsets (compared to a full scan).
 *
 * Both scans should be limited in time; both hold on to resource
 * for the duration of the scan, which can lead to resource
 * exhaustion / contention.
 *
 * [HSE_REVISIT] There should be an enforced time limit to auto-release
 * all resources after expiration.
 * [HSE_REVISIT] What are the exact effects of a full scan on a huge tree?
 */
merr_t
cn_cursor_create(
    struct cn *            cn,
    u64                    seqno,
    bool                   reverse,
    const void *           prefix,
    u32                    pfx_len,
    struct cursor_summary *summary,
    void **                cursorp)
{
    int           ct_pfx_len = cn->cp->cp_pfx_len;
    int           attempts = 5;
    struct pscan *cur;
    merr_t        err;

    cur = cn_pscan_create();
    if (ev(!cur))
        return merr(ENOMEM);

    assert(cur->bufsz >= HSE_KVS_KLEN_MAX + HSE_KVS_VLEN_MAX);

    /*
     * The pfxhash MUST be calculated on the configured tree pfx_len,
     * if it exists, else the requested prefix may search a different
     * finger down the tree.
     *
     * pfxhash, shift and mask are used to navigate the tree prefix path
     *
     * memory layout:
     *  cur     sizeof(cur)
     *  prefix  pfx_len
     *  keybuf  MAX_KEY_LEN
     *  valbuf  MAX_VAL_LEN
     */
    cur->pfxhash = pfx_hash64(prefix, pfx_len, ct_pfx_len);
    cur->pfx_len = pfx_len;
    cur->ct_pfx_len = ct_pfx_len;
    cur->pfx = prefix;

    cur->shift = cn_tree_fanout_bits(cn->cn_tree);
    cur->mask = (1 << cur->shift) - 1;

    /* for cursor update */
    cur->cn = cn;
    cur->seqno = seqno;

    cur->summary = summary;
    cur->reverse = reverse;

    /*
     * attempt to create the cursor several times:
     * certain race conditions with spill and compact
     * can cause the depth search to fail;
     * repeating should succeed in these cases
     */
    do {
        err = cn_tree_cursor_create(cur, cn->cn_tree);
    } while (merr_errno(err) == EAGAIN && --attempts > 0);

    if (ev(err)) {
        hse_elog(HSE_ERR "%s: attempts %d: @@e", err, __func__, attempts);
        cn_pscan_free(cur);
        return merr(EAGAIN);
    }

    ev(attempts < 5); /* cursor was successfully corrected */

    *cursorp = cur;
    return 0;
}

merr_t
cn_cursor_update(void *cursor, u64 seqno, bool *updated)
{
    struct pscan *cur = cursor;
    u64           dgen = atomic64_read(&cur->cn->cn_ingest_dgen);
    int           attempts = 5;
    merr_t        err;

    if (updated)
        *updated = false;

    /* a cursor in error, stays in error: must destroy/recreate */
    if (ev(cur->merr))
        return cur->merr;

    cur->seqno = seqno;

    /* common case: nothing changed, nothing to do */
    if (cur->dgen == dgen)
        return 0;

    do {
        err = cn_tree_cursor_update(cur, cur->cn->cn_tree);
    } while (merr_errno(err) == EAGAIN && --attempts > 0);

    ev(attempts != 5);

    if (updated)
        *updated = true;

    if (err && merr_errno(err) != EAGAIN) {
        hse_elog(HSE_ERR "%s: update failed (%p %lu): @@e",
                 err, __func__, cursor, seqno);
        cur->merr = err;
    }

    return err;
}

merr_t
cn_cursor_seek(
    void *             cursor,
    const void *       key,
    u32                len,
    struct kc_filter * filter,
    struct kvs_ktuple *kt)
{
    return cn_tree_cursor_seek(cursor, key, len, filter, kt);
}

merr_t
cn_cursor_read(void *cursor, struct kvs_kvtuple *kvt, bool *eof)
{
    return cn_tree_cursor_read(cursor, kvt, eof);
}

void
cn_cursor_destroy(void *cursor)
{
    struct pscan *cur = cursor;

    cn_tree_cursor_destroy(cur);
    free(cur->iterv);
    free(cur->esrcv);
    cn_pscan_free(cur);
}

merr_t
cn_cursor_active_kvsets(void *cursor, u32 *active, u32 *total)
{
    return cn_tree_cursor_active_kvsets(cursor, active, total);
}

merr_t
cn_make(struct mpool *ds, struct kvs_cparams *cp, struct kvdb_health *health)
{
    merr_t             err;
    struct cn_tree *   tree;
    u32                fanout_bits;
    struct kvs_rparams rp;
    struct kvs_cparams icp;

    assert(ds);
    assert(cp);
    assert(health);

    switch (cp->cp_fanout) {
        case 2:
            fanout_bits = 1;
            break;
        case 4:
            fanout_bits = 2;
            break;
        case 8:
            fanout_bits = 3;
            break;
        case 16:
            fanout_bits = 4;
            break;
        default:
            return merr(EINVAL);
    }

    /* Create and destroy a tree as a means of validating
     * prefix len, etc.
     */
    rp = kvs_rparams_defaults();

    icp.cp_fanout = 1 << fanout_bits;
    icp.cp_pfx_len = cp->cp_pfx_len;
    icp.cp_sfx_len = cp->cp_sfx_len;
    icp.cp_pfx_pivot = cp->cp_pfx_pivot;

    err = cn_tree_create(&tree, NULL, cn_cp2cflags(cp), &icp, health, &rp);
    if (!err)
        cn_tree_destroy(tree);

    return err;
}

u64
cn_mpool_dev_zone_alloc_unit_default(struct cn *cn, enum mp_media_classp mclass)
{
    return cn->cn_mpool_params.mp_mblocksz[mclass] << 20;
}

u64
cn_vma_mblock_max(struct cn *cn, enum mp_media_classp mclass)
{
    u64 vma_size_max, mblocksz;

    vma_size_max = 1ul << cn->cn_mpool_params.mp_vma_size_max;
    mblocksz = cn_mpool_dev_zone_alloc_unit_default(cn, mclass);

    assert(mblocksz > 0);

    return vma_size_max / mblocksz;
}

#if HSE_MOCKING
#include "cn_ut_impl.i"
#include "cn_cursor_ut_impl.i"
#include "cn_mblocks_ut_impl.i"
#endif /* HSE_MOCKING */
