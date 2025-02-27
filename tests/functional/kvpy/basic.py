#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

from contextlib import ExitStack
from hse2 import hse
from utility import lifecycle, cli

hse.init(cli.HOME)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "basic")
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"a", b"1")
        kvs.put(b"b", b"2")
        assert kvs.get(b"a") == b"1"
        assert kvs.get(b"b") == b"2"

        with kvs.cursor() as cur:
            kv = cur.read()
            assert kv == (b"a", b"1")
            kv = cur.read()
            assert kv == (b"b", b"2")
            cur.read()
            assert cur.eof
            cur.seek(b"a")
            kv = cur.read()
            assert kv == (b"a", b"1")
finally:
    hse.fini()
