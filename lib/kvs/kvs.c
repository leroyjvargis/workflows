/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * Exported API of the HSE struct ikvs
 */

#include <hse/hse.h>
#include <hse/kvdb_perfc.h>

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/string.h>
#include <hse_util/event_counter.h>
#include <hse_util/perfc.h>
#include <hse_util/darray.h>
#include <hse_util/timing.h>
#include <hse_util/fmt.h>
#include <hse_util/byteorder.h>
#include <hse_util/slab.h>
#include <hse_util/table.h>

#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/lc.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/key_hash.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/cursor.h>
#include <hse_ikvdb/wal.h>

/* "pkvsl" stands for Public KVS interface Latencies" */
struct perfc_name kvs_pkvsl_perfc_op[] = {
    NE(PERFC_LT_PKVSL_KVS_PUT, 3, "kvs_put latency", "kvs_put_lat", 7),
    NE(PERFC_LT_PKVSL_KVS_GET, 3, "kvs_get latency", "kvs_get_lat", 7),
    NE(PERFC_LT_PKVSL_KVS_DEL, 3, "kvs_delete latency", "kvs_del_lat", 7),

    NE(PERFC_LT_PKVSL_KVS_PFX_PROBE, 3, "kvs_prefix_probe latency", "kvs_pfx_probe_lat"),
    NE(PERFC_LT_PKVSL_KVS_PFX_DEL, 3, "kvs_prefix_delete latency", "kvs_pfx_del_lat"),

    NE(PERFC_LT_PKVSL_KVS_CURSOR_CREATE, 2, "kvs_cursor_create latency", "kvs_cursor_create_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_UPDATE, 2, "kvs_cursor_update latency", "kvs_cursor_update_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_SEEK, 2, "kvs_cursor_seek latency", "kvs_cursor_seek_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_READFWD,
       2,
       "kvs_cursor_read forward latency",
       "kvs_cursor_readfwd_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_READREV,
       2,
       "kvs_cursor_read reverse latency",
       "kvs_cursor_readrev_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_DESTROY,
       2,
       "kvs_cursor_destroy latency",
       "kvs_cursor_destroy_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_FULL, 2, "full cursor lifetime", "cursor_lifetime_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_INIT, 2, "kvs_cursor_init latency", "kvs_cursor_init_lat"),
};

NE_CHECK(
    kvs_pkvsl_perfc_op,
    PERFC_EN_PKVSL,
    "public kvs interface latencies perfc ops table/enum mismatch");

struct mpool;

/*-  Key Value Store  -------------------------------------------------------*/

static atomic_t kvs_init_ref;

static merr_t
kvs_create(struct ikvs **kvs, struct kvs_rparams *rp);

static void
kvs_destroy(struct ikvs *kvs);

static void
kvs_perfc_alloc(const char *kvdb_home, const char *kvs_name, struct ikvs *kvs)
{
    char   dbname_buf[DT_PATH_COMP_ELEMENT_LEN];
    size_t n;

    dbname_buf[0] = 0;

    n = strlcpy(dbname_buf, kvdb_home, sizeof(dbname_buf));
    if (ev(n >= sizeof(dbname_buf)))
        return;
    n = strlcat(dbname_buf, IKVDB_SUB_NAME_SEP, sizeof(dbname_buf));
    if (ev(n >= sizeof(dbname_buf)))
        return;
    n = strlcat(dbname_buf, kvs_name, sizeof(dbname_buf));
    if (ev(n >= sizeof(dbname_buf)))
        return;

    kvs_cursor_perfc_alloc(dbname_buf, &kvs->ikv_cc_pc, &kvs->ikv_cd_pc);

    /* Measure Public KVS interface Latencies */
    if (perfc_ctrseti_alloc(
            COMPNAME, dbname_buf, kvs_pkvsl_perfc_op, PERFC_EN_PKVSL, "set", &kvs->ikv_pkvsl_pc))
        hse_log(HSE_ERR "cannot alloc kvs perf counters");
}

/**
 * ikvs_maint_task() - periodic maintenance on ikvs
 *
 * Currently, this function is called with the ikdb_lock held, ugh...
 */
void
kvs_maint_task(struct ikvs *kvs, u64 now)
{
    cn_periodic(kvs->ikv_cn, now);
}

static void
kvs_perfc_free(struct ikvs *kvs)
{
    kvs_cursor_perfc_free(&kvs->ikv_cc_pc, &kvs->ikv_cd_pc);
    perfc_ctrseti_free(&kvs->ikv_pkvsl_pc);
}

/*
 * Resources allocated after a successful open are listed here in order of
 * allocation.  The kvs_close function must free resources listed on the
 * right side in reverse order of allocation.
 *
 *    Allocator              ->  Freer
 *    ---------                  ------
 *    kvs_create                 kvs_destroy
 *    cn_open                    cn_close
 *    c0_open                    c0_close
 *
 * [HSE_REVISIT]: Perhaps this arg list can be trimmed some ...
 */
merr_t
kvs_open(
    struct ikvdb *      kvdb,
    struct kvdb_kvs *   kvs,
    struct mpool *      ds,
    struct cndb *       cndb,
    struct lc *         lc,
    struct wal *        wal,
    struct kvs_rparams *rp,
    struct kvdb_health *health,
    struct cn_kvdb *    cn_kvdb,
    uint                flags)
{
    merr_t       err;
    struct ikvs *ikvs = 0;
    const char * kvs_name = kvdb_kvs_name(kvs);
    u64          cnid = kvdb_kvs_cnid(kvs);

    assert(kvdb);
    assert(health);

    err = kvs_create(&ikvs, rp);
    if (ev(err))
        goto err_exit;

    /* [HSE_REVISIT]: we need to remove dt entries if open fails, and also
     * in kvs_close().  In the meantime, do not fail the open if adding
     * dt entries fails.
     */

    ikvs->ikv_cnid = cnid;
    ikvs->ikv_kvs_name = strndup(kvs_name, HSE_KVS_NAME_LEN_MAX);
    ikvs->ikv_lc = lc;
    ikvs->ikv_wal = wal;

    if (!ikvs->ikv_kvs_name) {
        err = merr(ENOMEM);
        goto err_exit;
    }

    /* avoid using caller's rp struct.  use our copy in ikvs struct. */
    rp = 0;

    err = cn_open(
        cn_kvdb,
        ds,
        kvs,
        cndb,
        cnid,
        &ikvs->ikv_rp,
        ikvdb_home(kvdb),
        kvs_name,
        health,
        flags,
        &ikvs->ikv_cn);
    if (ev(err))
        goto err_exit;

    err = c0_open(kvdb, &ikvs->ikv_rp, ikvs->ikv_cn, ds, &ikvs->ikv_c0);
    if (ev(err))
        goto err_exit;

    ikvs->ikv_pfx_len = c0_get_pfx_len(ikvs->ikv_c0);
    ikvs->ikv_sfx_len = cn_get_sfx_len(ikvs->ikv_cn);

    err = qctx_te_mem_init();
    if (ev(err))
        goto err_exit;

    kvs_perfc_alloc(ikvdb_home(kvdb), kvs_name, ikvs);

    kvdb_kvs_set_ikvs(kvs, ikvs);

    return 0;

err_exit:
    if (ikvs) {
        if (ikvs->ikv_c0)
            c0_close(ikvs->ikv_c0);
        if (ikvs->ikv_cn)
            cn_close(ikvs->ikv_cn);
        kvs_destroy(ikvs);
    }

    return err;
}

struct cn *
kvs_cn(struct ikvs *ikvs)
{
    return ikvs ? ikvs->ikv_cn : 0;
}

uint64_t
kvs_cnid(const struct ikvs *ikvs)
{
    return ikvs->ikv_cnid;
}

/*
 * Resources freed by kvs_close:
 *    c0_close
 *    cn_close
 *    kvs_destroy
 */
merr_t
kvs_close(struct ikvs *ikvs)
{
    merr_t err = 0;

    if (ev(!ikvs))
        return merr(EINVAL);

    cn_disable_maint(ikvs->ikv_cn, true);

    kvs_cursor_reap(ikvs);

    err = c0_close(ikvs->ikv_c0);
    if (err)
        hse_elog(HSE_ERR "%s: c0_close @@e", err, __func__);

    err = cn_close(ikvs->ikv_cn);
    if (err)
        hse_elog(HSE_ERR "%s: cn_close @@e", err, __func__);

    kvs_perfc_free(ikvs);

    kvs_destroy(ikvs);

    return err;
}

struct perfc_set *
kvs_perfc_pkvsl(struct ikvs *ikvs)
{
    if (ikvs->ikv_rp.kvs_debug & 2)
        return &ikvs->ikv_pkvsl_pc;

    return NULL;
}

bool
kvs_txn_is_enabled(struct ikvs *kvs)
{
    return kvs->ikv_rp.transactions_enable;
}

merr_t
kvs_put(
    struct ikvs *              kvs,
    struct hse_kvdb_txn *const txn,
    struct kvs_ktuple *        kt,
    struct kvs_vtuple *        vt,
    uintptr_t                  seqnoref)
{
    struct kvdb_ctxn *ctxn = txn ? kvdb_ctxn_h2h(txn) : 0;
    struct perfc_set *pkvsl_pc = kvs_perfc_pkvsl(kvs);
    struct wal_record rec;
    size_t            sfx_len;
    size_t            hashlen;
    u64               tstart;
    u64               seqno;
    merr_t            err;

    tstart = perfc_lat_start(pkvsl_pc);

    sfx_len = kvs->ikv_sfx_len;
    hashlen = kt->kt_len - sfx_len;

    /* Assert that either
     *  1. This is NOT a suffixed tree, OR
     *  2. keylen is at least pfx_len + sfx_len
     */
    if (HSE_UNLIKELY(sfx_len && kt->kt_len < sfx_len + kvs->ikv_pfx_len)) {
#ifndef HSE_BUILD_RELEASE
        hse_log(HSE_ERR "%s: suffixed kvs %s %lu min key length is pfx_len(%u) + sfx_len(%u)",
                __func__,
                kvs->ikv_kvs_name,
                kvs->ikv_cnid,
                kvs->ikv_pfx_len,
                kvs->ikv_sfx_len);
#endif
        return merr(EINVAL);
    }

    kt->kt_hash = key_hash64(kt->kt_data, hashlen);
    seqno = 0;
    rec.cookie = -1;

    /* Exclusively lock txn for c0 update (with write collision detection).
     *
     * Note that we permute the hash with the ephemeral kvs unique generation
     * count to allow the caller to insert identical keys into more than one
     * kvs within the same transaction (despite which could falsely fail due
     * to hash collisions within the write conflict detection apparatus).
     */
    if (ctxn) {
        u64 hash = kt->kt_hash ^ kvs->ikv_gen;
        u64 pfxhash = 0;

        if (sfx_len > 0)
            hash = key_hash64_seed(kt->kt_data, kt->kt_len, kvs->ikv_gen);

        if (kvs->ikv_pfx_len && kt->kt_len >= kvs->ikv_pfx_len)
            pfxhash = key_hash64_seed(kt->kt_data, kvs->ikv_pfx_len, kvs->ikv_gen);

        err = kvdb_ctxn_trylock_write(ctxn, &seqnoref, &seqno, &rec.cookie, false, pfxhash, hash);
        if (err)
            return err;
    }

    err = wal_put(kvs->ikv_wal, kvs, kt, vt, seqno, &rec);

    if (HSE_LIKELY(!err)) {
        err = c0_put(kvs->ikv_c0, kt, vt, seqnoref);

        wal_op_finish(kvs->ikv_wal, &rec, kt->kt_seqno, kt->kt_dgen, merr_errno(err));
    }

    if (ctxn)
        kvdb_ctxn_unlock(ctxn);

    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_PUT, tstart);

    return err;
}

merr_t
kvs_get(
    struct ikvs *              kvs,
    struct hse_kvdb_txn *const txn,
    struct kvs_ktuple *        kt,
    u64                        seqno,
    enum key_lookup_res *      res,
    struct kvs_buf *           vbuf)
{
    struct kvdb_ctxn *ctxn = txn ? kvdb_ctxn_h2h(txn) : 0;
    struct perfc_set *pkvsl_pc = kvs_perfc_pkvsl(kvs);
    struct c0 *       c0 = kvs->ikv_c0;
    struct lc *       lc = kvs->ikv_lc;
    struct cn *       cn = kvs->ikv_cn;
    uintptr_t         seqnoref = 0;
    size_t            hashlen;
    u64               tstart;
    merr_t            err;

    tstart = perfc_lat_start(pkvsl_pc);

    hashlen = kt->kt_len - kvs->ikv_sfx_len;
    kt->kt_hash = key_hash64(kt->kt_data, hashlen);

    /* Exclusively lock txn for query.
     * seqnoref is invalid ater lock is released.
     */
    if (ctxn) {
        err = kvdb_ctxn_trylock_read(ctxn, &seqnoref, &seqno);
        if (err)
            return err;
    }

    err = c0_get(c0, kt, seqno, seqnoref, res, vbuf);

    if (!err && *res == NOT_FOUND)
        err = lc_get(lc, c0_index(c0), kvs->ikv_pfx_len, kt, seqno, seqnoref, res, vbuf);

    if (ctxn)
        kvdb_ctxn_unlock(ctxn);

    if (!err && *res == NOT_FOUND)
        err = cn_get(cn, kt, seqno, res, vbuf);

    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_GET, tstart);

    return err;
}

merr_t
kvs_del(struct ikvs *kvs, struct hse_kvdb_txn *const txn, struct kvs_ktuple *kt, uintptr_t seqnoref)
{
    struct perfc_set *pkvsl_pc = kvs_perfc_pkvsl(kvs);
    struct kvdb_ctxn *ctxn = txn ? kvdb_ctxn_h2h(txn) : 0;
    struct wal_record rec;
    size_t            sfx_len;
    size_t            hashlen;
    u64               tstart;
    u64               seqno;
    merr_t            err;

    tstart = perfc_lat_start(pkvsl_pc);

    sfx_len = kvs->ikv_sfx_len;
    hashlen = kt->kt_len - sfx_len;

    /* Assert that either
     *  1. This is NOT a suffixed tree, OR
     *  2. keylen is at least pfx_len + sfx_len
     */
    if (HSE_UNLIKELY(sfx_len && kt->kt_len < sfx_len + kvs->ikv_pfx_len)) {
#ifndef HSE_BUILD_RELEASE
        hse_log(HSE_ERR "%s: suffixed kvs %s %lu min key length is pfx_len(%u) + sfx_len(%u)",
                __func__,
                kvs->ikv_kvs_name,
                kvs->ikv_cnid,
                kvs->ikv_pfx_len,
                kvs->ikv_sfx_len);
#endif
        return merr(EINVAL);
    }

    kt->kt_hash = key_hash64(kt->kt_data, hashlen);
    seqno = 0;
    rec.cookie = -1;

    /* Exclusively lock txn for c0 update (with write collision detection).
     */
    if (ctxn) {
        u64 hash = kt->kt_hash ^ kvs->ikv_gen;
        u64 pfxhash = 0;

        if (sfx_len > 0)
            hash = key_hash64_seed(kt->kt_data, kt->kt_len, kvs->ikv_gen);

        if (kvs->ikv_pfx_len && kt->kt_len >= kvs->ikv_pfx_len)
            pfxhash = key_hash64_seed(kt->kt_data, kvs->ikv_pfx_len, kvs->ikv_gen);

        err = kvdb_ctxn_trylock_write(ctxn, &seqnoref, &seqno, &rec.cookie, false, pfxhash, hash);
        if (err)
            return err;
    }

    err = wal_del(kvs->ikv_wal, kvs, kt, seqno, &rec);
    if (!err) {
        err = c0_del(kvs->ikv_c0, kt, seqnoref);

        wal_op_finish(kvs->ikv_wal, &rec, kt->kt_seqno, kt->kt_dgen, merr_errno(err));
    }

    if (ctxn)
        kvdb_ctxn_unlock(ctxn);

    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_DEL, tstart);

    return err;
}

merr_t
kvs_prefix_del(
    struct ikvs               *kvs,
    struct hse_kvdb_txn *const txn,
    struct kvs_ktuple         *kt,
    uintptr_t                  seqnoref)
{
    struct perfc_set *pkvsl_pc = kvs_perfc_pkvsl(kvs);
    struct kvdb_ctxn *ctxn = txn ? kvdb_ctxn_h2h(txn) : 0;
    struct wal_record rec;
    u64               tstart;
    u64               seqno;
    merr_t            err;

    tstart = perfc_lat_start(pkvsl_pc);

    if (!kt->kt_hash)
        kt->kt_hash = key_hash64(kt->kt_data, kt->kt_len);

    seqno = 0;
    rec.cookie = -1;

    /* Exclusively lock txn for c0 update (no write collision detection.
     */
    if (ctxn) {
        u64 pfxhash = 0;

        if (kvs->ikv_pfx_len && kt->kt_len >= kvs->ikv_pfx_len)
            pfxhash = key_hash64_seed(kt->kt_data, kvs->ikv_pfx_len, kvs->ikv_gen);

        err = kvdb_ctxn_trylock_write(ctxn, &seqnoref, &seqno, &rec.cookie, true, pfxhash, 0);
        if (err)
            return err;
    }

    err = wal_del_pfx(kvs->ikv_wal, kvs, kt, seqno, &rec);
    if (!err) {
        err = c0_prefix_del(kvs->ikv_c0, kt, seqnoref);

        wal_op_finish(kvs->ikv_wal, &rec, kt->kt_seqno, kt->kt_dgen, merr_errno(err));
    }

    if (ctxn)
        kvdb_ctxn_unlock(ctxn);

    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_PFX_DEL, tstart);

    return ev(err);
}

merr_t
kvs_pfx_probe(
    struct ikvs *              kvs,
    struct hse_kvdb_txn *const txn,
    struct kvs_ktuple *        kt,
    u64                        seqno,
    enum key_lookup_res *      res,
    struct kvs_buf *           kbuf,
    struct kvs_buf *           vbuf)
{
    struct perfc_set *pkvsl_pc = kvs_perfc_pkvsl(kvs);
    struct kvdb_ctxn *ctxn = txn ? kvdb_ctxn_h2h(txn) : 0;
    struct c0 *       c0 = kvs->ikv_c0;
    struct lc *       lc = kvs->ikv_lc;
    struct cn *       cn = kvs->ikv_cn;
    uintptr_t         seqnoref = 0;
    struct query_ctx  qctx;
    u64               tstart;
    merr_t            err;

    tstart = perfc_lat_start(pkvsl_pc);

    if (HSE_UNLIKELY(kvs->ikv_sfx_len == 0)) {
#ifndef HSE_BUILD_RELEASE
        hse_log(HSE_ERR "%s: unsuffixed kvs %s %lu does not support prefix probe",
                __func__, kvs->ikv_kvs_name, kvs->ikv_cnid);
#endif
        return merr(EINVAL);
    }

    qctx.qtype = QUERY_PROBE_PFX;
    qctx.pos = qctx.ntombs = qctx.seen = 0;
    qctx.tomb_tree = RB_ROOT;

    if (!kt->kt_hash)
        kt->kt_hash = key_hash64(kt->kt_data, kt->kt_len);

    /* Exclusively lock txn for query.
     * seqnoref is invalid after lock is released.
     */
    if (ctxn) {
        err = kvdb_ctxn_trylock_read(ctxn, &seqnoref, &seqno);
        if (err)
            return err;
    }

    /* [HSE_REVISIT] There could be a ptomb in LC that has a higher seqno than a matching key in
     * c0. This will not be an issue once ptombs honor snapshot isolation.
     */
    err = c0_pfx_probe(c0, kt, seqno, seqnoref, res, &qctx, kbuf, vbuf);
    if (err || *res == FOUND_PTMB || qctx.seen > 1)
        goto exit;

    err = lc_pfx_probe(lc, kt, c0_index(c0), seqno, seqnoref, c0_get_pfx_len(c0),
                       c0_get_sfx_len(c0), res, &qctx, kbuf, vbuf);
    if (err || *res == FOUND_PTMB || qctx.seen > 1)
        goto exit;

    err = cn_pfx_probe(cn, kt, seqno, res, &qctx, kbuf, vbuf);
    if (err || *res == FOUND_PTMB || qctx.seen > 1)
        goto exit;

    qctx_te_mem_reset();

exit:
    if (ctxn)
        kvdb_ctxn_unlock(ctxn);

    if (ev(err))
        return err;

    perfc_rec_sample(&kvs->ikv_cd_pc, PERFC_DI_CD_TOMBSPERPROBE, qctx.ntombs);

    switch (qctx.seen) {
        case 0:
            *res = NOT_FOUND;
            break;
        case 1:
            *res = FOUND_VAL;
            break;
        default:
            *res = FOUND_MULTIPLE;
    }

    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_PFX_PROBE, tstart);

    return 0;
}

static merr_t
kvs_create(struct ikvs **ikvs_out, struct kvs_rparams *rp)
{
    static atomic64_t g_ikv_gen;
    struct ikvs *     ikvs;

    *ikvs_out = NULL;

    ikvs = aligned_alloc(alignof(*ikvs), sizeof(*ikvs));
    if (ev(!ikvs))
        return merr(ENOMEM);

    memset(ikvs, 0, sizeof(*ikvs));
    ikvs->ikv_gen = atomic64_inc_return(&g_ikv_gen);
    ikvs->ikv_rp = *rp;

    *ikvs_out = ikvs;

    return 0;
}

static void
kvs_destroy(struct ikvs *kvs)
{
    if (ev(!kvs)) {
        assert(kvs);
        return;
    }

    free((void *)kvs->ikv_kvs_name);
    free(kvs);
}

void
kvs_perfc_init(void)
{
    kvs_cursor_perfc_init();
}

void
kvs_perfc_fini(void)
{
    kvs_cursor_perfc_fini();
}

merr_t
kvs_init(void)
{
    merr_t err;

    if (atomic_inc_return(&kvs_init_ref) > 1)
        return 0;

    err = kvs_curcache_init();
    if (ev(err))
        atomic_dec(&kvs_init_ref);

    return err;
}

void
kvs_fini(void)
{
    if (atomic_dec_return(&kvs_init_ref) > 0)
        return;

    kvs_curcache_fini();
}
