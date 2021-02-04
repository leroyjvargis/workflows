/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/event_counter.h>
#include <hse_util/hse_err.h>

#include "omf.h"

merr_t
omf_mdc_loghdr_pack_htole(struct mdc_loghdr *lh, char *outbuf)
{
    struct mdc_loghdr_omf *lhomf;

    lhomf = (struct mdc_loghdr_omf *)outbuf;

    if (ev(lh->vers != MDC_LOGHDR_VERSION))
        return merr(EINVAL);

    omf_set_lh_vers(lhomf, lh->vers);
    omf_set_lh_magic(lhomf, lh->magic);
    omf_set_lh_rsvd(lhomf, lh->rsvd);
    omf_set_lh_gen(lhomf, lh->gen);
    omf_set_lh_crc(lhomf, lh->crc);

    return 0;
}

void
omf_mdc_loghdr_unpack_letoh(struct mdc_loghdr *lh, const char *inbuf)
{
    struct mdc_loghdr_omf *lhomf;

    lhomf = (struct mdc_loghdr_omf *)inbuf;

    lh->vers = omf_lh_vers(lhomf);
    lh->magic = omf_lh_magic(lhomf);
    lh->rsvd = omf_lh_rsvd(lhomf);
    lh->gen = omf_lh_gen(lhomf);
    lh->crc = omf_lh_crc(lhomf);
}

void
omf_mdc_rechdr_pack_htole(struct mdc_rechdr *rh, char *outbuf)
{
    struct mdc_rechdr_omf *rhomf;

    rhomf = (struct mdc_rechdr_omf *)outbuf;

    omf_set_rh_crc(rhomf, rh->crc);
    omf_set_rh_size(rhomf, rh->size);
}

void
omf_mdc_rechdr_unpack_letoh(struct mdc_rechdr *rh, const char *inbuf)
{
    struct mdc_rechdr_omf *rhomf;

    rhomf = (struct mdc_rechdr_omf *)inbuf;

    rh->crc = omf_rh_crc(rhomf);
    rh->size = omf_rh_size(rhomf);
}
