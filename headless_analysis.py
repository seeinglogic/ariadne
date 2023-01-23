#!/usr/bin/python3

'''
Perform Ariadne analysis via headless script (requires commercial BN license)
and save the result to a file for faster loading later.

Helpful for pre-processing on a server or remote machine.

Can also incorporate coverage analysis from bncov as part of the analysis.
'''

from typing import Optional
import argparse
import math
import os
import sys
import time

import binaryninja

sys.path.insert(0, binaryninja.user_plugin_path())

coverage_enabled = False
try:
    import bncov
    coverage_enabled = True
except ImportError:
    try:
        import ForAllSecure_bncov as bncov
        coverage_enabled = True
    except ImportError:
        pass

import ariadne


USAGE = f'{sys.argv[0]} TARGET_FILE [COVERAGE_DIR]'


def pretty_size(filename):
    filesize = os.path.getsize(filename)
    if filesize == 0:
       return "0B"
    suffix = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    unit_index = int(math.floor(math.log(filesize, 1024)))
    unit_size = math.pow(1024, unit_index)
    rounded_size = round(filesize / unit_size, 2)
    return f'{rounded_size} {suffix[unit_index]}'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('TARGET', help='Binary or bndb to analyze and save data for')
    parser.add_argument('-c', '--coverage_dir', help='Directory containing coverage files for target')
    parser.add_argument('--load_existing', help='Load cached Ariadne analysis file', action='store_true')
    parser.add_argument('--overwrite_existing', help='Overwrite cached Ariadne analysis file (if it exists)',
                        action="store_true")
    parser.add_argument
    args = parser.parse_args()

    target = args.TARGET
    coverage_dir: Optional[str] = args.coverage_dir
    if coverage_dir:
        # Check that we have bncov first, then that the directory exists
        if coverage_enabled:
            if not os.path.exists(coverage_dir):
                print(f'[!] Coverage dir "{coverage_dir}" not found')
                exit(2)
            else:
                num_files = len(os.listdir(coverage_dir))
                print(f'[*] Coverage dir: "{coverage_dir}" ({num_files} files)')
        else:
            print(f'[!] Couldn\'t import bncov, coverage data will be ignored')

    open_start = time.time()
    print(f'[*] Loading BinaryView for "{target}" ({pretty_size(target)})...')
    bv = binaryninja.open_view(target)
    duration = time.time() - open_start
    print(f'[*] Completed in {duration:.02f} seconds')

    if coverage_dir:
        coverage_start = time.time()
        print(f'[*] Starting coverage import...')
        covdb = bncov.get_covdb(bv)
        covdb.add_directory(coverage_dir)
        duration = time.time() - coverage_start
        num_files = len(os.listdir(coverage_dir))
        num_blocks = len(covdb.total_coverage)
        print(f'[*] Processed {num_files} coverage files ({num_blocks} blocks) in {duration:.02f} seconds')

    print('[*] Instantiating Ariadne core')
    core = ariadne.AriadneCore()

    if args.load_existing:
        core.force_load_from_cache = True
    if args.overwrite_existing:
        core.force_cache_overwrite = True

    print('[*] Queuing analysis')
    analysis_start = time.time()
    core.queue_analysis(bv)

    print('[*] Waiting for Ariadne analysis to complete', end='')
    i = 0
    while True:
        time.sleep(0.1)
        i += 1
        if bv in core.targets:
            break
        if (i % 10) == 0:
            sys.stdout.write('.')
            sys.stdout.flush()
    duration = time.time() - open_start
    print(f'\n[*] Completed in {duration:.02f} seconds')

    core.save_analysis_to_file(bv)

    saved_file = core.get_cache_target(bv)
    if os.path.exists(saved_file):
        print(f'[+] Analysis file: {saved_file} (size: {pretty_size(saved_file)})')
    else:
        print(f'[-] Failed to save file to expected location ({saved_file})')
