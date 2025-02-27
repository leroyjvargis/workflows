/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <hse_util/logging.h>
#include <hse_ikvdb/mclass_policy.h>
#include <hse_ikvdb/param.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/vcomp_params.h>
#include <hse_util/storage.h>

/*
 * Steps to add a new kvs run-time parameter(rparam):
 * 1. Add a new struct element to struct kvs_rparams.
 * 2. Add a new entry to pspecs.
 */

static bool
validate_cn_node_size_lo(const struct param_spec *ps, const union params params)
{
    assert(ps);
    assert(params.as_kvs_rp);

    if (params.as_kvs_rp->cn_node_size_lo > params.as_kvs_rp->cn_node_size_hi) {
        hse_log(
            HSE_ERR "cn_node_size_lo(%lu) must be less"
                    " than or equal to cn_node_size_hi(%lu)",
            (ulong)params.as_kvs_rp->cn_node_size_lo,
            (ulong)params.as_kvs_rp->cn_node_size_hi);
        return false;
    }

    return true;
}

static bool
validate_cn_node_size_hi(const struct param_spec *ps, const union params params)
{
    assert(ps);
    assert(params.as_kvs_rp);

    if (params.as_kvs_rp->cn_node_size_hi < params.as_kvs_rp->cn_node_size_lo) {
        hse_log(
            HSE_ERR "cn_node_size_hi(%lu) must be greater"
                    " than or equal to cn_node_size_lo(%lu)",
            (ulong)params.as_kvs_rp->cn_node_size_hi,
            (ulong)params.as_kvs_rp->cn_node_size_lo);
        return false;
    }

    return true;
}

static const struct param_spec pspecs[] = {
    {
        .ps_name = "kvs_debug",
        .ps_description = "enable kvs debugging",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, kvs_debug),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->kvs_debug),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "kvs_cursor_ttl",
        .ps_description = "cached cursor time-to-live (ms)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, kvs_cursor_ttl),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->kvs_cursor_ttl),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 1500,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "transactions_enable",
        .ps_description = "enable transactions for the kvs",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, transactions_enable),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->transactions_enable),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "cn_node_size_lo",
        .ps_description = "low end of max node size range (MiB)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_node_size_lo),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_node_size_lo),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_validate_relations = validate_cn_node_size_lo,
        .ps_default_value = {
            .as_uscalar = 20 * 1024.
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_node_size_hi",
        .ps_description = "high end of max node size range (MiB)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_node_size_hi),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_node_size_hi),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_validate_relations = validate_cn_node_size_hi,
        .ps_default_value = {
            .as_uscalar = 28 * 1024,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_compact_vblk_ra",
        .ps_description = "compaction vblk read-ahead (bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_compact_vblk_ra),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_compact_vblk_ra),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 256 * 1024,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_compact_vra",
        .ps_description = "compaction vblk read-ahead via mcache",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_compact_vra),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_compact_vra),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 128 * 1024,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_compact_kblk_ra",
        .ps_description = "compaction kblk read-ahead (bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_compact_kblk_ra),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_compact_kblk_ra),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 512 * 1024,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_capped_ttl",
        .ps_description = "cn cursor cache TTL (ms) for capped kvs",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_capped_ttl),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_capped_ttl),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 9000,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_capped_vra",
        .ps_description = "capped cursor vblk madvise-ahead (bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_capped_vra),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_capped_vra),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 512 * 1024,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_cursor_vra",
        .ps_description = "compaction vblk read-ahead via mcache",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_cursor_vra),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_cursor_vra),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_cursor_kra",
        .ps_description = "cursor kblk madvise-ahead (boolean)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_cursor_kra),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_cursor_kra),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "cn_cursor_seq",
        .ps_description = "optimize cn_tree for longer sequential cursor accesses",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_cursor_seq),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_cursor_seq),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_mcache_wbt",
        .ps_description = "eagerly cache wbt nodes (1:internal, 2:leaves, 3:both)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_mcache_wbt),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_mcache_wbt),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 1,
                .ps_max = 3,
            },
        },
    },
    {
        .ps_name = "cn_mcache_vminlvl",
        .ps_description = "node depth at/above which to read vmin length values directly from media",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_mcache_vminlvl),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_mcache_vminlvl),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = U16_MAX,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_mcache_vmin",
        .ps_description = "value size at/above which to read values directly from media (subject to vminlvl)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_mcache_vmin),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_mcache_vmin),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 256,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max= UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_mcache_vmax",
        .ps_description = "value size at/above which to always read values directly from media",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_mcache_vmax),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_mcache_vmax),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 4096,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_mcache_kra_params",
        .ps_description = "kblock readahead [pct][lev1][lev0]",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_mcache_kra_params),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_mcache_kra_params),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = (50u << 16) | (4u << 8) | 4u,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_mcache_vra_params",
        .ps_description = "vblock readahead [pct][lev1][lev0]",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_mcache_vra_params),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_mcache_vra_params),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = (40u << 16) | (2u << 8) | 1u,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_diag_mode",
        .ps_description = "enable/disable cn diag mode",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_diag_mode),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_diag_mode),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "cn_maint_disable",
        .ps_description = "disable cn maintenance",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_maint_disable),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_maint_disable),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "cn_bloom_create",
        .ps_description = "enable bloom creation",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_bloom_create),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_bloom_create),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 1,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "cn_bloom_lookup",
        .ps_description = "control bloom lookup (0:off, 1:mcache, 2:read)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_bloom_lookup),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_bloom_lookup),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 2,
            },
        },
    },
    {
        .ps_name = "cn_bloom_prob",
        .ps_description = "bloom create probability",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_bloom_prob),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_bloom_prob),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 10000,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_bloom_capped",
        .ps_description = "bloom create probability (capped kvs)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_bloom_capped),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_bloom_capped),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_bloom_preload",
        .ps_description = "preload mcache bloom filters",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_bloom_preload),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_bloom_preload),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_compaction_debug",
        .ps_description = "cn compaction debug flags",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_compaction_debug),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_compaction_debug),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_maint_delay",
        .ps_description = "ms of delay between checks when idle",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_maint_delay),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_maint_delay),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 100,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 20,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_io_threads",
        .ps_description = "number of cn mblock i/o threads",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_io_threads),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_io_threads),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 13,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_close_wait",
        .ps_description = "force close to wait until all active compactions have completed",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_close_wait),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_close_wait),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_verify",
        .ps_description = "verify kvsets as they are created",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_verify),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_verify),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "cn_kcachesz",
        .ps_description = "max per-kvset key cache size (in bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_kcachesz),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->cn_kcachesz),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 1024 * 1024,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "kblock_size_mb",
        .ps_description = "preferred kblock size (in MiB)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, kblock_size),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->kblock_size),
        .ps_convert = param_convert_to_bytes_from_MB,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 32 * MB,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = KBLOCK_MIN_SIZE,
                .ps_max = KBLOCK_MAX_SIZE,
            },
        },
    },
    {
        .ps_name = "vblock_size_mb",
        .ps_description = "",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, vblock_size),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->vblock_size),
        .ps_convert = param_convert_to_bytes_from_MB,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 32 * MB,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = VBLOCK_MIN_SIZE,
                .ps_max = VBLOCK_MAX_SIZE,
            },
        },
    },
    {
        .ps_name = "capped_evict_ttl",
        .ps_description = "",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, capped_evict_ttl),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->capped_evict_ttl),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 120,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "kv_print_config",
        .ps_description = "print kvs runtime params",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, kv_print_config),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->kv_print_config),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 1,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "rdonly",
        .ps_description = "open kvs in read-only mode",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, rdonly),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->rdonly),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "mclass_policy",
        .ps_description = "media class policy",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_ENUM,
        .ps_offset = offsetof(struct kvs_rparams, mclass_policy),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_enum = "capacity_only",
        },
        .ps_bounds = {
            .as_enum = {
                .ps_num_values = 4,
                .ps_values = {
                    /* stolen from lib/kvdb/mclass_policy.c */
                    "capacity_only",
                    "staging_only",
                    "staging_max_capacity",
                    "staging_min_capacity",
                },
            },
        },
    },
    {
        .ps_name = "vcompmin",
        .ps_description = "value length above which compression is considered",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, vcompmin),
        .ps_size = sizeof(((struct kvs_rparams *) 0)->vcompmin),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 12,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "value_compression",
        .ps_description = "value compression algorithm (lz4 or none)",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_ENUM,
        .ps_offset = offsetof(struct kvs_rparams, value_compression),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_enum = VCOMP_PARAM_NONE,
        },
        .ps_bounds = {
            .as_enum = {
                .ps_values = {
                    VCOMP_PARAM_NONE,
                    VCOMP_PARAM_LZ4,
                },
                .ps_num_values = 2,
            },
        },
    },
};

const struct param_spec *
kvs_rparams_pspecs_get(size_t *pspecs_sz)
{
    if (pspecs_sz)
        *pspecs_sz = NELEM(pspecs);
    return pspecs;
}

struct kvs_rparams
kvs_rparams_defaults()
{
    struct kvs_rparams params;
    const union params p = { .as_kvs_rp = &params };
    param_default_populate(pspecs, NELEM(pspecs), p);
    return params;
}
