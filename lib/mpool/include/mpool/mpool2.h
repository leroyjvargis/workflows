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

merr_t
mpool_open2(const char *name, const struct hse_params *params, struct mpool **handle);

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

#endif /* HSE_MPOOL2_H */
