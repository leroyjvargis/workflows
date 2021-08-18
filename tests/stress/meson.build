programs = {
    'stress_reverse_cursor_unlimited_txn': {
        'small_tests': {
            'reverse_cursor_unlimited_txn_small': {
                'args': '-a 1000 -b 64 -c 5000000 -d 2 -o 2 -v 1024'.split(),
            },
        },
        'large_tests': {
            # 'reverse_cursor_unlimited_txn_large': {
            #     'args': '-a 1000 -b 64 -c 1000000000 -d 100 -o 100 -v 1024'.split(),
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
