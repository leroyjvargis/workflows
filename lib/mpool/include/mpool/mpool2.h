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

struct mpool;
struct mpool_params;

merr_t
mpool_params_get2(struct mpool *mp, struct mpool_params *params);

merr_t
mpool_params_set2(struct mpool *mp, struct mpool_params *params);

#endif /* HSE_MPOOL2_H */
