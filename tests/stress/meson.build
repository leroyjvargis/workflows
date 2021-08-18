programs = {
    'stress_wal': {
        'small_tests': {
            'noclose_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 0 -o 2 -r 0 -s 0 -t 0 -v 1024'.split(),
            },
            'txn_noclose_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 0 -o 2 -r 0 -s 20 -t 1 -v 1024'.split(),
            },
            'disablewal_syncbeforeexit_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 1 -o 2 -r 1 -s 0 -t 0 -v 1024'.split(),
            },
            'txn_disablewal_syncbeforeexit_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 1 -o 2 -r 1 -s 16 -t 1 -v 1024'.split(),
            },
            'interleave_aborted_txns_noclose_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 0 -o 2 -r 0 -s 16 -t 2 -v 1024'.split(),
            },
            'interleave_aborted_txns_disablewal_syncbeforeexit_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 1 -o 2 -r 1 -s 16 -t 2 -v 1024'.split(),
            },
            'txn_noclose_tinyrecords_noclose_small': {
                'args': '-b 8 -c 9999000 -e 0 -i 0 -o 2 -r 0 -s 16 -t 1 -v 16'.split(),
            },
            'txn_noclose_tinyrecords_disablewal_syncbeforeexit_small': {
                'args': '-b 8 -c 9999000 -e 0 -i 1 -o 2 -r 1 -s 16 -t 1 -v 16'.split(),
            },
            'txn_noclose_1k2k_noclose_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 0 -o 2 -r 0 -s 16 -t 1 -v 2048 -p 64 -q 1024'.split(),
            },
            'txn_noclose_1k2k_disablewal_syncbeforeexit_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 1 -o 2 -r 1 -s 16 -t 1 -v 2048 -p 64 -q 1024'.split(),
            },
            'multikvs_noclose_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 0 -o 2 -r 0 -s 64 -t 4 -v 1024'.split(),
            },
            'multikvs_disablewal_syncbeforeexit_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 1 -o 2 -r 1 -s 64 -t 4 -v 1024'.split(),
            },
        },
        'large_tests': {
            'noclose_large': {
                'args': '-b 64 -c 1000000000 -e 0 -i 0 -o 100 -r 0 -s 0 -t 0 -v 1024'.split(),
            },
            # 'txn_noclose_large': {
            #     'args': '-b 64 -c 1000000000 -e 0 -i 0 -o 100 -r 0 -s 0 -t 1 -v 1024'.split(),
            # },
            'disablewal_syncbeforeexit_large': {
                'args': '-b 64 -c 1000000000 -e 0 -i 1 -o 100 -r 1 -s 0 -t 0 -v 1024'.split(),
            },
            # 'txn_disablewal_syncbeforeexit_large': {
            #     'args': '-b 64 -c 1000000000 -e 0 -i 1 -o 100 -r 1 -s 0 -t 1 -v 1024'.split(),
            # },
            # 'multikvs_noclose_large': {
            #     'args': '-b 64 -c 1000000000 -e 0 -i 0 -o 100 -r 0 -s 128 -t 4 -v 1024'.split(),
            # },
            # 'multikvs_disablewal_syncbeforeexit_large': {
            #     'args': '-b 64 -c 1000000000 -e 0 -i 1 -o 100 -r 1 -s 128 -t 4 -v 1024'.split(),
            # },
        },
    },
    
}

foreach p, p_params: programs
    e = executable(
        p,
        ['@0@.c'.format(p), 'stress_util.c'],
        c_args: [
            '-D_GNU_SOURCE=1',
        ],
        dependencies: [hse_static_dep, hse_dependencies],
    )

    foreach t, t_params : p_params['small_tests']
        test(
            t,
            e,
            args: t_params['args'],
            is_parallel: false,
            suite: ['stress'],
            timeout: params.get('timeout', 1800),
        )
    endforeach

    foreach t, t_params : p_params['large_tests']
        test(
            t,
            e,
            args: t_params['args'],
            is_parallel: false,
            suite: ['stress_large'],
            timeout: params.get('timeout', 3600),
        )
    endforeach
endforeach
