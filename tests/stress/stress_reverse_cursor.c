/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <getopt.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>

#include <hse/hse.h>
#include "stress_util.h"

#define MAX_KEY_LEN HSE_KVS_KLEN_MAX
#define MAX_VAL_LEN 4096
#define MAX_THREAD  500

extern int  DEBUG;
atomic_int  error_count;
atomic_int  verification_failure_count;
atomic_long inserted_record_count;
atomic_long queries_count;

struct cursor_test_data {
    char *           kvdb_home;
    char *           kvs_name;
    long int         key_count;
    int              val_size;
    int              point_insertion_thread_count;
    int              cursor_read_thread_count;
    int              key_size;
    int              wal_disable;
    int              uncommitted;
    int              rank;
    long int         start;
    long int         end;
    long int         key_count_per_thread;
    struct hse_kvs * kvs;
    struct hse_kvdb *kvdb;
    char             data[MAX_VAL_LEN];
};

void
print_usage(void)
{
    printf("Usage: stress_reverse_cursor\n"
           " -b <key size>\n"
           " -c <key count>\n"
           " -C <kvdb_home>\n"
           " -d <cursor read thread count>\n"
           " -n <uncommitted>     if 1, don't commit after put\n"
           " -o <point_insertion_thread_count>\n"
           " -r <wal_disable>\n"
           " -u <debug>\n"
           " -v <value_size>\n");
}

long int
get_first_key_index(long int key_count_per_thread, int thread_index)
{
    long int i, firstkey = 1, lastkey = 0;

    for (i = 0; i < thread_index; i++) {
        lastkey = firstkey + key_count_per_thread - 1;
        firstkey = lastkey + 1;
    }
    return firstkey;
}

void
cursor_read(void *args, struct hse_kvs_cursor *CURSOR)
{
    struct cursor_test_data *info = args;
    long int                 i = 0;
    const void *             cur_key, *cur_val;
    size_t                   cur_klen, cur_vlen;
    char                     expected_key_buf[info->key_size];
    char                     expected_val_buf[info->val_size];
    bool                     eof = false;
    hse_err_t                err;
    char                     msg[100];

    log_info("begin %s", __func__);

    if (error_count > 0 || verification_failure_count > 0)
        return;

    for (i = info->end - 1; i >= info->start; i--) {
        generate_record(
            expected_key_buf,
            sizeof(expected_key_buf),
            expected_val_buf,
            sizeof(expected_val_buf),
            info->key_size,
            info->val_size,
            info->data,
            i);

        if (i == info->end - 1) {
            if (DEBUG) {
                log_debug(
                    "hse_kvs_cursor_seek: rank=%d key_index=%ld key=\"%s\"",
                    info->rank,
                    i,
                    expected_key_buf);
            }

            err = hse_kvs_cursor_seek(
                CURSOR, HSE_FLAG_NONE, expected_key_buf, info->key_size, NULL, NULL);

            if (err) {
                hse_strerror(err, msg, sizeof(msg));
                log_error(
                    "hse_kvs_cursor_seek: errno=%d msg=\"%s\" "
                    "rank=%d expected_key=\"%s\"",
                    hse_err_to_errno(err),
                    msg,
                    info->rank,
                    expected_key_buf);
                ++error_count;
                break;
            }
        }

        err = hse_kvs_cursor_read(
            CURSOR, HSE_FLAG_NONE, &cur_key, &cur_klen, &cur_val, &cur_vlen, &eof);

        if (err) {
            hse_strerror(err, msg, sizeof(msg));
            log_error(
                "hse_kvs_cursor_read: errno=%d msg=\"%s\" rank=%d key_index=%ld",
                hse_err_to_errno(err),
                msg,
                info->rank,
                i);
            ++error_count;
            break;
        } else if (DEBUG) {
            log_debug(
                "hse_kvs_cursor_read: rank=%d key_index=%ld key=\"%s\"", info->rank, i, cur_key);
        }

        if (eof) {
            log_error(
                "kvs cursor read unexpected EOF: rank=%d start=%ld end=%ld failed=%ld",
                info->rank,
                info->start,
                info->end,
                i);
            ++verification_failure_count;
            break;
        }

        if (info->key_size != cur_klen || info->val_size != cur_vlen) {
            log_error(
                "FAILED key length verification: "
                "actual_key_len=%ld expected_key_len=%ld",
                cur_klen,
                info->key_size);
            ++verification_failure_count;
            break;
        } else if (info->val_size != cur_vlen) {
            log_error(
                "FAILED value length verfication: "
                "actual_val_len=%ld expected_val_len=%ld",
                cur_vlen,
                info->val_size);
            ++verification_failure_count;
            break;
        } else if (memcmp(expected_key_buf, cur_key, info->key_size) != 0) {
            log_error(
                "FAILED key verification: start=%ld end=%ld i=%d "
                "key=\"%s\" expected_key=\"%s\"",
                info->start,
                info->end,
                i,
                cur_key,
                expected_key_buf);
            ++verification_failure_count;
            break;
        } else if (memcmp(expected_val_buf, cur_val, info->val_size) != 0) {
            log_error(
                "FAILED value verification: start=%ld end=%ld i=%d "
                "key=\"%s\" value=\"%s\" expected_value=\"%s\"",
                info->start,
                info->end,
                i,
                cur_key,
                cur_val,
                expected_val_buf);
            ++verification_failure_count;
            break;
        }

        ++queries_count;
    }

    log_info("end %s", __func__);
}

void
point_insertion(void *args)
{
    struct cursor_test_data *info = (struct cursor_test_data *)args;
    long int                 i = 0;
    struct hse_kvdb_txn *    txn;
    struct hse_kvs_cursor *  CURSOR;
    char                     key_buf[info->key_size];
    char                     val_buf[info->val_size];
    hse_err_t                err;
    char                     msg[100];

    log_info("begin %s", __func__);

    if (error_count > 0 || verification_failure_count > 0)
        goto out;

    txn = hse_kvdb_txn_alloc(info->kvdb);
    if (txn == NULL) {
        log_error("hse_kvdb_txn_alloc failed");
        ++error_count;
        goto out;
    }

    err = hse_kvdb_txn_begin(info->kvdb, txn);

    if (err) {
        hse_strerror(err, msg, sizeof(msg));
        log_error(
            "hse_kvdb_txn_begin: errno=%d msg=\"%s\" rank=%d",
            hse_err_to_errno(err),
            msg,
            info->rank);
        ++error_count;
        goto out2;
    } else if (DEBUG) {
        log_debug("hse_kvdb_txn_begin: rank=%d txn=%d", info->rank);
    }

    for (i = info->start; i < info->end; i++) {
        generate_record(
            key_buf,
            sizeof(key_buf),
            val_buf,
            sizeof(val_buf),
            info->key_size,
            info->val_size,
            info->data,
            i);

        if (DEBUG) {
            log_debug("hse_kvs_put: rank=%d key_index=%ld key=\"%s\"", info->rank, i, key_buf);
        }

        err = hse_kvs_put(
            info->kvs, HSE_FLAG_NONE, txn, key_buf, sizeof(key_buf), val_buf, sizeof(val_buf));

        if (err) {
            hse_strerror(err, msg, sizeof(msg));
            log_error(
                "hse_kvs_put: errno=%d msg=\"%s\" rank=%d key=\"%s\"",
                hse_err_to_errno(err),
                msg,
                info->rank,
                key_buf);
            ++error_count;
            goto out2;
        }

        ++inserted_record_count;
    }

    if (DEBUG) {
        log_debug("hse_kvs_cursor_create: rank=%d", info->rank);
    }

    err = hse_kvs_cursor_create(info->kvs, HSE_CURSOR_CREATE_REV, txn, NULL, 0, &CURSOR);
    if (err) {
        hse_strerror(err, msg, sizeof(msg));
        log_error(
            "hse_kvs_cursor_create: errno=%d msg=\"%s\" rank=%d",
            hse_err_to_errno(err),
            msg,
            info->rank);
        ++error_count;
        goto out2;
    }

    if (!info->uncommitted) {
        err = hse_kvdb_txn_commit(info->kvdb, txn);

        if (err) {
            hse_strerror(err, msg, sizeof(msg));
            log_error(
                "hse_kvdb_txn_commit: errno=%d msg=\"%s\" rank=%d",
                hse_err_to_errno(err),
                msg,
                info->rank);
            ++error_count;
            goto out3;
        } else if (DEBUG) {
            log_debug("hse_kvdb_txn_commit: rank=%d", info->rank);
        }
    }

    cursor_read(args, CURSOR);

out3:
    err = hse_kvs_cursor_destroy(CURSOR);

    if (err) {
        hse_strerror(err, msg, sizeof(msg));
        log_error(
            "hse_kvs_cursor_destroy: errno=%d msg=\"%s\" rank=%d cursor_idx=%d",
            hse_err_to_errno(err),
            msg,
            info->rank,
            i);
        ++error_count;
    } else if (DEBUG) {
        log_debug("hse_kvs_cursor_destroy: rank=%d", info->rank);
    }

out2:
    hse_kvdb_txn_free(info->kvdb, txn);

    if (DEBUG) {
        log_debug("hse_kvdb_txn_free: rank=%d", info->rank);
    }

out:
    log_info("end %s", __func__);
}

long int
get_count_per_x(long int long_count, int x)
{
    long int count_per_x = long_count;

    if (long_count % x)
        count_per_x = long_count + (x - long_count % x);

    return count_per_x / x;
}

void
spawn_threads(struct cursor_test_data *params, void *thread_fun, char *fun_name)
{
    pthread_t               thread_info[MAX_THREAD];
    int                     thread;
    char                    buf[100];
    struct cursor_test_data args[MAX_THREAD];
    int                     thread_count = 0;
    int                     rc;
    int                     n;

    if (strcmp(fun_name, "point_insertion") == 0)
        thread_count = params->point_insertion_thread_count;
    else
        thread_count = params->cursor_read_thread_count;

    log_info("spawning %d thread(s), fun_name=\"%s\"", thread_count, fun_name);

    for (thread = 0; thread < thread_count; thread++) {
        params->key_count_per_thread = get_count_per_x(params->key_count, thread_count);
        params->rank = thread;
        params->start = get_first_key_index(params->key_count_per_thread, thread);
        params->end = params->start + params->key_count_per_thread;

        memcpy(&args[thread], params, sizeof(struct cursor_test_data));
        memcpy(&args[thread].data, params->data, sizeof(params->data));

        pthread_create(&thread_info[thread], NULL, thread_fun, (void *)&args[thread]);

        n = snprintf(buf, sizeof(buf), "%s-%03d", fun_name, thread);
        assert(n < sizeof(buf));
        n = n; /* unused */

        pthread_setname_np(thread_info[thread], buf);
    }
    for (thread = 0; thread < thread_count; thread++) {
        rc = pthread_join(thread_info[thread], 0);
        if (rc)
            log_error("pthread_join error: error=%d", rc);
    }

    log_info("completed wait for %d spawned thread(s), fun_name=\"%s\"", thread_count, fun_name);
}

int
execute_test(struct cursor_test_data *params)
{
    struct hse_kvdb *kvdb;
    int              status;
    int              result;
    hse_err_t        hse_err;
    char             msg[100];

    result = 0;

    srand(time(NULL));
    fillrandom(params->data, sizeof(params->data));

    status = create_or_open_kvdb_and_kvs(
        params->kvdb_home, params->kvs_name, &kvdb, &params->kvs, true, params->wal_disable, 1);

    if (status) {
        log_fatal("kvdb+kvs open failed: errno=%d", status);
        return 1;
    }

    params->kvdb = kvdb;

    spawn_threads(params, point_insertion, "point_insertion");

    if (error_count > 0) {
        result = 1;
        log_error("FAILED after %d error(s)", error_count);
    } else if (verification_failure_count > 0) {
        result = 1;
        log_error("FAILED after %d verification failure(s)", verification_failure_count);
    } else
        log_info("PASSED verification");

    log_info("closing kvs \"%s\" in \"%s\"", params->kvs_name, params->kvdb_home);
    hse_err = hse_kvdb_kvs_close(params->kvs);
    if (hse_err) {
        hse_strerror(hse_err, msg, sizeof(msg));
        log_error("hse_kvdb_kvs_close: errno=%d msg=\"%s\"", hse_err_to_errno(hse_err), msg);
    }

    log_info("closing kvdb \"%s\"", params->kvdb_home);
    hse_err = hse_kvdb_close(kvdb);
    if (hse_err) {
        hse_strerror(hse_err, msg, sizeof(msg));
        log_error("hse_kvdb_close: errno=%d msg=\"%s\"", hse_err_to_errno(hse_err), msg);
    }

    return result;
}

int
main(int argc, char *argv[])
{
    int                     option = 0;
    struct cursor_test_data para;
    hse_err_t               err;
    int                     status;
    int                     mod;

    memset(&para, 0, sizeof(para));

    para.key_count = 1000;
    para.kvs_name = "cursor_kvs";
    para.key_size = 10;
    para.val_size = 100;

    while ((option = getopt(argc, argv, "b:c:C:d:n:o:r:t:u:v:")) != -1) {
        switch (option) {
            case 'b':
                para.key_size = atoi(optarg);
                break;

            case 'c':
                para.key_count = atoi(optarg);
                break;

            case 'C':
                para.kvdb_home = optarg;
                break;

            case 'd':
                para.cursor_read_thread_count = atoi(optarg);
                break;

            case 'n':
                para.uncommitted = atoi(optarg);
                break;

            case 'o':
                para.point_insertion_thread_count = atoi(optarg);
                break;

            case 'r':
                para.wal_disable = atoi(optarg);
                break;

            case 'u':
                DEBUG = atoi(optarg);
                break;

            case 'v':
                para.val_size = atoi(optarg);
                break;

            default:
                print_usage();
                exit(EXIT_FAILURE);
        }
    }

    if (argc == 1) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    log_info("cursor_read_thread_count      = %d", para.cursor_read_thread_count);
    log_info("debug                         = %d", DEBUG);
    log_info("key_count                     = %d", para.key_count);
    log_info("key_size                      = %d", para.key_size);
    log_info("kvdb_home                     = \"%s\"", para.kvdb_home);
    log_info("kvs_name                      = \"%s\"", para.kvs_name);
    log_info("point_insertion_thread_count  = %d", para.point_insertion_thread_count);
    log_info("uncommitted                   = %d", para.uncommitted);
    log_info("val_size                      = %d", para.val_size);
    log_info("wal_disable                   = %d", para.wal_disable);
    log_info("");

    assert(para.key_size > 0 || para.key_count > 0 || para.val_size > 0);

    mod = para.key_count % para.point_insertion_thread_count;

    if (mod) {
        para.key_count += para.point_insertion_thread_count - mod;
        log_info("adjusted key_count to %d due to insertion thread count", para.key_count);
        log_info("");
    }

    err = hse_init(para.kvdb_home, 0, NULL);

    if (err) {
        log_fatal("hse_init: errno=%d", hse_err_to_errno(err));
        exit(EXIT_FAILURE);
    }

    status = execute_test(&para);

    hse_fini();

    exit(status);
}
