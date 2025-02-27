run_env.append('PYTHONPATH', meson.current_source_dir())

test_runner = find_program('test-runner')
pytest = find_program('pytest', required: true)
bash = find_program('bash')
sh = find_program('sh') # write POSIX-compliant when easily doable

# Suites to exclude based on varying factors
additional_suite_exclusions = []

if get_option('b_sanitize') != 'none'
    # Enabling hse-python based tests in sanitized builds needs to be
    # investigated. Issues with PYTHON_MALLOC_ and LD_PRELOAD.
    additional_suite_exclusions += 'python'
    additional_suite_exclusions += 'hse-python'

    if get_option('b_sanitize').contains('undefined')
        run_env.append('UBSAN_OPTIONS', 'suppressions=@0@/suppressions/hse.undefined.supp'.format(meson.project_source_root()))
        run_env.append('UBSAN_OPTIONS', 'print_stacktrace=1')
    endif
endif

add_test_setup(
    'default',
    exe_wrapper: [
        test_runner,
        '--',
    ],
    env: run_env,
    is_default: true,
    # TODO: Check with Meson 0.59 else PR to Meson...
    exclude_suites: ['long', 'non-deterministic', 'stress', 'stress_large'] + additional_suite_exclusions,
)

add_test_setup(
    'ci',
    exe_wrapper: [
        test_runner,
        '--',
    ],
    env: run_env,
    is_default: false,
    # TODO: Check with Meson 0.59 else PR to Meson...
    exclude_suites: ['long', 'smoke', 'non-deterministic', 'stress', 'stress_large'] + additional_suite_exclusions,
)

if in_ci
    run_env.append('MESON_TESTTHREADS', 1)
endif

add_test_setup(
    'cinightly',
    env: run_env,
    is_default: false,
    exclude_suites: ['unit', 'api'] + additional_suite_exclusions,
)

subdir('unit')
subdir('functional')
subdir('stress')
subdir('benchmarks')
