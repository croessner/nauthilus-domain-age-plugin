#!/usr/bin/env python3
"""Enroll existing ICANN credentials directly into the owner's SOPS secret."""
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys

OWNER = Path('/Users/croessner/GoLandProjects/nauthilus-tests/kubernetes')
RELATIVE = Path('secrets/prod/nauthilus-czds.sops.yaml')
RECIPIENT = 'age1dyza3v0yg7a6flghm8hgrd9eruyl7xt0dheaz5cqpghwqsqft3dsqpa54d'


def main():
    """Prompt privately, encrypt in memory, and exclusively persist ciphertext."""
    if not sys.stdin.isatty():
        raise RuntimeError('Run this helper in your own interactive terminal')
    branch = subprocess.check_output(['git', '-C', str(OWNER), 'branch', '--show-current'], text=True).strip()
    if branch != 'features' or (OWNER / RELATIVE).exists():
        raise RuntimeError('Expected features branch and a new secret destination')
    username = input('ICANN account email: ').strip()
    password = getpass.getpass('Existing ICANN password (hidden): ')
    if not username or not password:
        raise RuntimeError('Both existing account fields are required')
    document = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'nauthilus-czds', 'namespace': 'auth'}, 'type': 'Opaque', 'stringData': {'username': username, 'password': password}}
    result = subprocess.run(['sops', '--encrypt', '--age', RECIPIENT, '--encrypted-regex', '^(data|stringData)$', '--input-type', 'json', '--output-type', 'json', '--filename-override', str(RELATIVE), '/dev/stdin'], cwd=OWNER, input=json.dumps(document).encode(), capture_output=True)
    if result.returncode:
        raise RuntimeError('SOPS encryption failed; no plaintext file written')
    encrypted = json.loads(result.stdout)
    if any(not encrypted['stringData'][key].startswith('ENC[') for key in ['username', 'password']):
        raise RuntimeError('Encryption validation failed')
    fd = os.open(OWNER / RELATIVE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(result.stdout)
        output.flush()
        os.fsync(output.fileno())
    print('Encrypted CZDS credential saved. No plaintext file was created.')


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt):
        sys.exit('CZDS credential enrollment stopped; no credential values are printed.')
