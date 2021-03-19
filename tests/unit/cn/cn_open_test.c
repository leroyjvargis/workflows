/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/allocation.h>
#include <hse_test_support/mock_api.h>

#include <hse_util/platform.h>
#include <hse_util/slab.h>

#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/kvdb_health.h>

#include <cn/cn_tree.h>
#include <cn/cn_tree_create.h>
#include <cn/cn_internal.h>
#include <cn/cn_perfc.h>

static int
init(struct mtf_test_info *lcl_ti)
{
    return 0;
}

static int
fini(struct mtf_test_info *lcl_ti)
{
    return 0;
}

/* cn_open params */
struct mpool *     ds;
struct kvdb_kvs *  kk;
struct cndb *      cndb;
u64                cnid;
struct kvs_rparams rp_struct, *rp;
const char *       mp;
const char *       kvs;
struct kvdb_health health, *h;
uint               flags;
struct kvs_cparams cp = {
    .cp_fanout = 16,
};

#define CN_OPEN_ARGS 0, ds, kk, cndb, cnid, rp, mp, kvs, h, flags

/* Prefer the mapi_inject_list method for mocking functions over the
 * MOCK_SET/MOCK_UNSET macros if the mock simply needs to return a
 * constant value.  The advantage of the mapi_inject_list approach is
 * less code (no need to define a replacement function) and easier
 * maintenance (will not break when the mocked function signature
 * changes).
 */
struct mapi_injection inject_list[] = {
    { mapi_idx_ikvdb_get_csched, MAPI_RC_PTR, (void *)-1 },
    { mapi_idx_ikvdb_kvdb_handle, MAPI_RC_PTR, (void *)-1 },
    { mapi_idx_ikvdb_get_mclass_policy, MAPI_RC_PTR, (void *)5 },
    { mapi_idx_kvdb_kvs_cparams, MAPI_RC_PTR, &cp },

    { mapi_idx_mpool_params_get, MAPI_RC_SCALAR, 0 },
    { mapi_idx_mpool_mclass_get, MAPI_RC_SCALAR, ENOENT },

    { mapi_idx_kvdb_kvs_flags, MAPI_RC_SCALAR, 0 },

    { mapi_idx_cndb_cn_instantiate, MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_getref, MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_putref, MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_cn_blob_get, MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_cn_blob_set, MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_cn_close, MAPI_RC_SCALAR, 0 },

    { mapi_idx_cn_tree_set_initial_dgen, MAPI_RC_SCALAR, 0 },

    { mapi_idx_csched_tree_add, MAPI_RC_SCALAR, 0 },
    { mapi_idx_csched_tree_remove, MAPI_RC_SCALAR, 0 },
    { mapi_idx_ikvdb_rdonly, MAPI_RC_SCALAR, 0 },
    { mapi_idx_ikvdb_rdonly, MAPI_RC_SCALAR, 0 },

    { -1 }
};

static void
setup_mocks(void)
{
    mapi_inject_clear();
    mapi_inject_list_set(inject_list);
}

static int
pre(struct mtf_test_info *lcl_ti)
{
    setup_mocks();

    ds = (void *)-1;
    kk = (void *)-1;
    cndb = (void *)-1;
    cnid = 1;
    rp_struct = kvs_rparams_defaults();
    rp = &rp_struct;
    mp = "mpxx";
    kvs = "kvsxx";
    memset(&health, 0, sizeof(health));
    h = &health;
    flags = 0;

    return 0;
}

static int
post(struct mtf_test_info *lcl_ti)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(cn_open_test, init, fini);

MTF_DEFINE_UTEST_PREPOST(cn_open_test, cn_open_basic, pre, post)
{
    merr_t     err;
    struct cn *cn;

    /* test w/ caller provided rparams */
    err = cn_open(CN_OPEN_ARGS, &cn);
    ASSERT_EQ(err, 0);
    cn_close(cn);

    /* test w/ rp == 0 */
    rp = 0;
    err = cn_open(CN_OPEN_ARGS, &cn);
    ASSERT_EQ(err, 0);

    cn_close(cn);
}

MTF_DEFINE_UTEST_PREPOST(cn_open_test, cn_open_repeat, pre, post)
{
    merr_t     err;
    struct cn *cn;
    int        i;

    for (i = 0; i < 5; i++) {
        err = cn_open(CN_OPEN_ARGS, &cn);
        ASSERT_EQ(err, 0);
        cn_close(cn);
    }
}

MTF_DEFINE_UTEST_PREPOST(cn_open_test, cn_open_rp, pre, post)
{
    merr_t     err;
    struct cn *cn;

    /* test w/ rp == 0 */
    rp = 0;
    err = cn_open(CN_OPEN_ARGS, &cn);
    ASSERT_EQ(err, 0);
    cn_close(cn);
}

MTF_DEFINE_UTEST_PREPOST(cn_open_test, cn_open_enomem, pre, post)
{
    merr_t     err;
    struct cn *cn;
    uint       i, num_allocs;

    /* cn_open requires `num_allocs` memory allocations. Expose each one
     * and verify we tested them all.
     */
    num_allocs = 7 + 20; /* 10 perfc set * 2 allocations per set. */

    for (i = 0; i <= num_allocs; i++) {

        mapi_inject_once_ptr(mapi_idx_malloc, i + 1, 0);

        err = cn_open(CN_OPEN_ARGS, &cn);

        if (i == num_allocs || (i > 0 && i < 21)) {
            ASSERT_EQ(err, 0);
            cn_close(cn);
        } else {
            ASSERT_EQ(merr_errno(err), ENOMEM);
        }

        mapi_inject_unset(mapi_idx_malloc);
    }

    ASSERT_EQ(err, 0);
}

MTF_DEFINE_UTEST_PREPOST(cn_open_test, cn_open_err_path, pre, post)
{
    merr_t     err;
    struct cn *cn;

    setup_mocks();
    mapi_inject(mapi_idx_cn_tree_create, 123);
    err = cn_open(CN_OPEN_ARGS, &cn);
    ASSERT_EQ(err, 123);

    setup_mocks();
    mapi_inject(mapi_idx_cndb_cn_instantiate, 123);
    err = cn_open(CN_OPEN_ARGS, &cn);
    ASSERT_EQ(err, 123);
}

static merr_t
ts_prepare(struct cn_tstate_omf *omf, void *arg)
{
    int *rcp = arg;

    return merr(*rcp);
}

static void
ts_commit(const struct cn_tstate_omf *omf, void *arg)
{
}

static void
ts_abort(struct cn_tstate_omf *omf, void *arg)
{
    int *rcp = arg;

    *rcp = EAGAIN;
}

MTF_DEFINE_UTEST_PREPOST(cn_open_test, cn_tstate_update, pre, post)
{
    int        rc;
    merr_t     err;
    struct cn *cn;

    err = cn_open(CN_OPEN_ARGS, &cn);
    ASSERT_EQ(err, 0);

    rc = 0;

    err = cn->cn_tstate->ts_update(NULL, ts_prepare, ts_commit, ts_abort, &rc);
    ASSERT_EQ(err, 0);

    err = cn->cn_tstate->ts_update(cn->cn_tstate, NULL, ts_commit, ts_abort, &rc);
    ASSERT_EQ(merr_errno(err), EINVAL);

    err = cn->cn_tstate->ts_update(cn->cn_tstate, ts_prepare, NULL, ts_abort, &rc);
    ASSERT_EQ(merr_errno(err), EINVAL);

    err = cn->cn_tstate->ts_update(cn->cn_tstate, ts_prepare, ts_commit, NULL, &rc);
    ASSERT_EQ(merr_errno(err), EINVAL);

    err = cn->cn_tstate->ts_update(cn->cn_tstate, ts_prepare, ts_commit, ts_abort, &rc);
    ASSERT_EQ(err, 0);

    rc = 0;
    mapi_inject_once(mapi_idx_cndb_cn_blob_set, 1, EIO);
    err = cn->cn_tstate->ts_update(cn->cn_tstate, ts_prepare, ts_commit, ts_abort, &rc);
    ASSERT_EQ(merr_errno(err), EIO);
    ASSERT_EQ(rc, EAGAIN);

    rc = EBUSY;
    mapi_inject(mapi_idx_cndb_cn_blob_set, 0);
    err = cn->cn_tstate->ts_update(cn->cn_tstate, ts_prepare, ts_commit, ts_abort, &rc);
    ASSERT_EQ(merr_errno(err), rc);

    cn_close(cn);
}

MTF_END_UTEST_COLLECTION(cn_open_test)
