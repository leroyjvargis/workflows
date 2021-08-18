programs = {    
    'stress_cursor': {
        'small_tests': {
            'create_cursor_small': {
                'args': '-b 64 -c 5000000 -d 1 -e 10000 -o 2 -v 1024'.split(),
            },
            'cursor_with_sync_small': {
                'args': '-b 64 -c 5000000 -d 5 -e 10000 -o 2 -v 1024'.split(),
            },
            'cursor_with_transactions_small': {
                'args': '-b 64 -c 100000 -d 6 -e 10000 -o 2 -s 10000 -v 1024'.split(),
            },
        },
        'large_tests': {
            'create_cursor_large': {
                'args': '-b 64 -c 1000000000 -d 1 -e 20000 -o 100 -v 1024'.split(),
            },
        },
    }    
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
