/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CONFIG_HSE_GPARAMS_H
#define HSE_CONFIG_HSE_GPARAMS_H

#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>

#include <hse_util/logging_types.h>
#include <hse_util/compiler.h>

struct hse_gparams {
	struct {
		bool enabled;
		/* bool structured; */
		enum log_destination destination;
		log_priority_t level;
		uint64_t squelch_ns;
		char path[PATH_MAX];
	} logging;
};

extern struct hse_gparams hse_gparams;

const struct param_spec *
hse_gparams_pspecs_get(size_t *pspecs_sz) HSE_RETURNS_NONNULL;

#endif
