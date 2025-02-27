/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_LIMITS_H
#define HSE_LIMITS_H

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup LIMITS Limits
 * @{
 */


/** @brief  Maximum number of KVS's contained within one KVDB.
 */
#define HSE_KVS_COUNT_MAX (256)

/* A common requirement clients have for key length is 1024.
 * Combined with a discriminant and (potentially) a chunk key, this pushes us to
 * 1030 bytes keys. Looking at the packing for the on-media format for data, we
 * can have at most 3 keys of such large size in a 4k page. Lopping off 64-bytes
 * for other data, and we can have 3 keys of 1344 bytes.
 */
/** @brief Maximum key length.
 *
 * Keys need not be NULL-terminated.
 */
#define HSE_KVS_KEY_LEN_MAX 1344

/** @brief Max value length is 1MiB
 *
 * Values need not be NULL-terminated.
 */
#define HSE_KVS_VALUE_LEN_MAX (1024 * 1024)

/** @brief Max key prefix length */
#define HSE_KVS_PFX_LEN_MAX 32

/** @brief Maximum length of a KVS name
 *
 * KVS names are NULL-terminated strings.  The string plus the NULL-terminator
 * must fit into a @p HSE_KVS_NAME_LEN_MAX byte buffer.
 */
#define HSE_KVS_NAME_LEN_MAX 32

/** @} LIMITS */

#ifdef __cplusplus
}
#endif

#endif
