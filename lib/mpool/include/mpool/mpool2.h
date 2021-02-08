/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
/*
 * Storage manager interface for HSE
 */

#ifndef HSE_MPOOL2_H
#define HSE_MPOOL2_H

#include <hse_util/hse_err.h>

#include "mpool_internal.h"

struct mpool;
struct hse_params;
struct mpool_params;
struct mpool_mdc;

merr_t
mpool_open2(const char *name, const struct hse_params *params, int flags, struct mpool **handle);

merr_t
mpool_close2(struct mpool *handle);

merr_t
mpool_destroy2(struct mpool *handle);

merr_t
mpool_params_get2(struct mpool *mp, struct mpool_params *params);

merr_t
mpool_params_set2(struct mpool *mp, struct mpool_params *params);

merr_t
mpool_mdc_alloc2(
    struct mpool           *mp,
    u32                     magic,
    size_t                  capacity,
    enum mp_media_classp    mclassp,
    uint64_t               *logid1,
    uint64_t               *logid2);

merr_t
mpool_mdc_commit2(struct mpool *mp, uint64_t logid1, uint64_t logid2);

merr_t
mpool_mdc_delete2(struct mpool *mp, uint64_t logid1, uint64_t logid2);

merr_t
mpool_mdc_abort2(struct mpool *mp, uint64_t logid1, uint64_t logid2);

merr_t
mpool_mdc_open2(
    struct mpool        *mp,
    uint64_t             logid1,
    uint64_t             logid2,
    struct mpool_mdc   **handle);

merr_t
mpool_mdc_close2(struct mpool_mdc *mdc);

merr_t
mpool_mdc_cstart2(struct mpool_mdc *mdc);

merr_t
mpool_mdc_cend2(struct mpool_mdc *mdc);

merr_t
mpool_mdc_rootid_get(struct mpool *mp, uint64_t *logid1, uint64_t *logid2);

merr_t
mpool_mdc_usage2(struct mpool_mdc *mdc, size_t *usage);

merr_t
mpool_mdc_append2(struct mpool_mdc *mdc, void *data, ssize_t len, bool sync);

merr_t
mpool_mdc_read2(struct mpool_mdc *mdc, void *data, size_t len, size_t *rdlen);

merr_t
mpool_mdc_rewind2(struct mpool_mdc *mdc);

merr_t
mpool_mdc_sync2(struct mpool_mdc *mdc);

#endif /* HSE_MPOOL2_H */
