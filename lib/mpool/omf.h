/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_OMF_H
#define MPOOL_OMF_H

#include <hse_util/omf.h>


/*
 * MDC OMF
 */

#define MDC_LOGHDR_MAGIC   ((u32)0xdeadbeef)
#define MDC_LOGHDR_VERSION ((u32)1)

struct mdc_loghdr_omf {
	__le32 lh_crc;
	__le32 lh_vers;
	__le32 lh_magic;
	__le32 lh_rsvd;
	__le64 lh_gen;
} __packed;

/* Define set/get methods for mdc_loghdr_omf */
OMF_SETGET(struct mdc_loghdr_omf, lh_crc, 32);
OMF_SETGET(struct mdc_loghdr_omf, lh_vers, 32);
OMF_SETGET(struct mdc_loghdr_omf, lh_magic, 32);
OMF_SETGET(struct mdc_loghdr_omf, lh_rsvd, 32);
OMF_SETGET(struct mdc_loghdr_omf, lh_gen, 64);


struct mdc_rechdr_omf {
	__le32 rh_crc;
	__le32 rh_size;
} __packed;

/* Define set/get methods for mdc_rechdr_omf */
OMF_SETGET(struct mdc_rechdr_omf, rh_crc, 32);
OMF_SETGET(struct mdc_rechdr_omf, rh_size, 32);

#endif /* MPOOL_OMF_H */
