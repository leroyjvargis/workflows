subdir('kvpy')
subdir('smoke')
subdir('api')

tests = {
    'kvs_compare_full_and_pfx': {
        'suites': ['python', 'long'],
        'depends': hse_python_depends,
    },
    'kvs_scan_deleted_keys': {
        'suites': ['python', 'short'],
        'depends': hse_python_depends,
    },
    'kvs_scan_empty_kvs': {
        'suites': ['python', 'short'],
        'depends': hse_python_depends,
    },
    # [HSE_TODO]: Invalid tests; I think this is because of compaction not being
    # synchonous.
    # 'kvs_compressed_values_take_less_space': {
    #     'suites': ['hse-python', 'short'],
    #     'depends': hse_python_depends,
    # },
    # 'kvs_compression_flags': {
    #     'suites': ['hse-python', 'short'],
    #     'depends': hse_python_depends,
    # },
    'kvs_scan_a_million': {
        'suites': ['python', 'long'],
        'depends': hse_python_depends,
    },
}

foreach t, params : tests
    test(
        t,
        python,
        args: [
            '@0@.py'.format(t),
        ],
        workdir: meson.current_source_dir(),
        depends: params.get('depends', []),
        suite: ['functional'] + params.get('suites', []),
        timeout: 3600,
        env: environment({
            'HSE_TEST_RUNNER_RUNNER': 'python',
        }),
        is_parallel: false,
    )
endforeach
