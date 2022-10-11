#!/usr/bin/env python3

import os
import shutil

from pathlib import Path

from binaryninja import user_plugin_path


bncov_repo_url = 'https://github.com/ForAllSecure/bncov.git'
plugin_dir = Path(user_plugin_path())

git_path = shutil.which('git')
if git_path is None:
    print(f'[!] Couldn\'t detect git path, bailing...')
    print(f'    Otherwise just manually change directory to "{plugin_dir}"')
    print(f'    and run "git clone {bncov_repo_url}"')

expected_dest = os.path.join(plugin_dir, 'bncov')
if os.path.exists(expected_dest):
    print(f'[!] bncov dir already exists? ({expected_dest})')
    #exit(-2)

print(f'[*] Cloning bncov to plugin directory "{plugin_dir}"')

os.chdir(plugin_dir)

git_clone_command = f'git clone {bncov_repo_url}'
print(f'[*] Running: "{git_clone_command}"')
retval = os.system(git_clone_command)
print(f'[*] Return code of git clone command: {retval}')
