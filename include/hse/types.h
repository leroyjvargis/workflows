/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_TYPES_H
#define HSE_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

/** @defgroup ERROR_HANDLING HSE Return Codes
 * @{
 * Describes the HSE API return code type and associated utilities.
 */


/** @typedef hse_err_t
 * @brief Generic return type for the HSE library
 *
 * If this scalar quantity is 0 then the call succeeded. If it is non-zero then the
 * 64-bit quantity can be used by the client in two ways: (1) call hse_err_to_errno() to
 * get a mapping to a POSIX errno value, and (2) call hse_err_to_string() to get a
 * textual reference about what error occurred and where.
 *
 * The following special errno error codes are worth mentioning here.
 *
 * <table>
 *   <tr><th>errno</th><th>Caller action</th></tr>
 *   <tr><td>EAGAIN</td><td>The caller is expected to retry the operation.</td></tr>
 *   <tr><td>ECANCELED</td><td> The caller is expected to retry the operation in a
 *   new transaction. See @ref WRITE_CONFLICT "write conflicts".</td></tr>
 * </table>
 *
 * e.g., the code snippet below shows a typical non-transactional usage:
 *
 * @code{.c}
 * int retries = 0;
 * hse_err_t ret = 0;
 *
 * while (retries < MAX_RETRIES) {
 *    ret = hse_kvs_put(kvs_handle, flags, txn, key, k_len, val, v_len)
 *    if (EAGAIN != hse_err_to_errno(ret))
 *       break;
 *    retries++;
 * }
 * @endcode
 */
typedef uint64_t hse_err_t;

/**@} ERROR_HANDLING */


/** @defgroup TYPES Type Declarations, Shared Structures and Macros.
 * @{
 * These types are generally opaque handles that a client obtains by using library
 * functions. A client uses these handles to exercise more fine-grained
 * functionality. For example a "struct hse_kvdb" is the handle for a key-value database
 * that one obtains by calling hse_kvdb_open().
 */

/** @struct hse_kvdb
 * @brief Opaque structure, a pointer to which is a handle to an HSE key-value
 *        database (KVDB).
 */
struct hse_kvdb;

/** @struct hse_kvs
 * @brief Opaque structure, a pointer to which is a handle to an HSE key-value
 *        store within a KVDB (KVS).
 */
struct hse_kvs;

/** @struct hse_kvs_cursor
 * @brief Opaque structure, a pointer to which is a handle to a cursor within
 *        a KVS.
 */
struct hse_kvs_cursor;

/** @struct hse_kvdb_txn
 * @brief Opaque structure, a pointer to which is a handle to a transaction
 *        within a KVDB.
 */
struct hse_kvdb_txn;

/** @} TYPES */

/** @addtogroup TXN
 * @{
 */

/** @brief Transaction state. */
enum hse_kvdb_txn_state {
    HSE_KVDB_TXN_INVALID = 0,
    HSE_KVDB_TXN_ACTIVE = 1,
    HSE_KVDB_TXN_COMMITTED = 2,
    HSE_KVDB_TXN_ABORTED = 3,
};

/** @} TXN */

#ifdef HSE_EXPERIMENTAL
/**
 * struct hse_kvdb_compact_status - status of a compaction request
 */
struct hse_kvdb_compact_status {
    unsigned int kvcs_samp_lwm;  /**< space amp low water mark (%) */
    unsigned int kvcs_samp_hwm;  /**< space amp high water mark (%) */
    unsigned int kvcs_samp_curr; /**< current space amp (%) */
    unsigned int kvcs_active;    /**< is an externally requested compaction underway */
    unsigned int kvcs_canceled;  /**< was an externally requested compaction canceled */
};
#endif

/**
 * struct hse_kvdb_storage_info - storage info for a kvdb
 */
struct hse_kvdb_storage_info {
    uint64_t total_bytes;     /**< total space in the file-system containing this kvdb */
    uint64_t available_bytes; /**< available space in the file-system containing this kvdb */
    uint64_t allocated_bytes; /**< allocated storage space for a kvdb */
    uint64_t used_bytes;      /**< used storage space for a kvdb */
};

#ifdef HSE_EXPERIMENTAL
enum hse_kvs_pfx_probe_cnt {
    HSE_KVS_PFX_FOUND_ZERO = 0,
    HSE_KVS_PFX_FOUND_ONE,
    HSE_KVS_PFX_FOUND_MUL,
};
#endif

#ifdef __cplusplus
}
#endif

#endif
