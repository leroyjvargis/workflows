if not get_option('tools')
    warning('benchmarks have been disabled because tools are disabled')
    subdir_done()
elif not get_option('cli')
    warning('benchmarks have been disabled because the CLI is disabled')
    subdir_done()
endif

tests = {
    'test_kmt_ro': {
        'suite': 'kmt',
        'timeout': 600,
        'depends': [
            tool_targets['kmt'],
        ],
    },
    'test_kmt_rw': {
        'suite': 'kmt',
        'timeout': 600,
        'depends': [
            tool_targets['kmt'],
        ],
    },
    'test_ycsb_2tb_putget': {
        'suite': 'ycsb',
        'timeout': 0,
        'depends': [
            hse_cli,
        ],
    },
    'test_ycsb_2tb_scan': {
        'suite': 'ycsb',
        'timeout': 0,
        'depends': [
            hse_cli,
        ],
    },
    'test_dbbench': {
        'suite': 'dbbench',
        'timeout': 0,
    },
}

foreach t, params : tests
    path = meson.current_source_dir() / '@0@.py'.format(t)
    testname = fs.stem(path)

    benchmark(
        testname,
        python,
        args: [
            path,
        ],
        env: run_env,
        depends: [hse_python_depends, params.get('depends', [])],
        suite: params.get('suite', ''),
        timeout: params.get('timeout', 60),
    )
endforeach
