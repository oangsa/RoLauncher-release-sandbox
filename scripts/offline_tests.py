"""Offline-only regression runner; no GitHub operations or enrolled keys."""
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent


def deny_network(*args, **kwargs):
    raise AssertionError('Network access is forbidden in offline regressions')


def main():
    socket.socket.connect = deny_network
    socket.socket.connect_ex = deny_network
    socket.create_connection = deny_network
    socket.getaddrinfo = deny_network
    for name in ('GITHUB_TOKEN', 'GH_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN',
                 'SSH_AUTH_SOCK', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE',
                 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES'):
        os.environ.pop(name, None)
    # Unit tests must not inherit owner hooks, signing configuration or a remote Git directory.
    os.environ.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                      GIT_CONFIG_SYSTEM=os.devnull, GIT_TERMINAL_PROMPT='0')
    original_popen = subprocess.Popen
    class OfflineProcess(original_popen):
        def __init__(self, args, *positional, **kwargs):
            if isinstance(args, (str, bytes)) or kwargs.get('shell') or kwargs.get('executable') or kwargs.get('preexec_fn'):
                raise AssertionError('Shell execution is forbidden in offline regressions')
            executable = str(args[0])
            name = Path(executable).name.lower()
            if executable != sys.executable and name not in ('git', 'git.exe', 'ssh-keygen', 'ssh-keygen.exe'):
                raise AssertionError('Unexpected offline subprocess')
            if name in ('git', 'git.exe') and set(args[1:]) & {
                    'clone', 'fetch', 'push', 'pull', 'ls-remote', 'remote', 'submodule'}:
                raise AssertionError('Remote Git operation forbidden in offline regressions')
            super().__init__(args, *positional, **kwargs)
    subprocess.Popen = OfflineProcess
    names = ('test-release-promotion.py', 'test-hotfix-policy.py',
             'test-owner-evidence.py', 'test-sandbox-port.py', 'test-phase-d.py')
    suite = unittest.TestSuite()
    for name in names:
        spec = importlib.util.spec_from_file_location(name.removesuffix('.py').replace('-', '_'), ROOT / 'scripts' / name)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
