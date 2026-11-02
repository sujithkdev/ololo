"""Start the local Docker lab; keep installation credentials out of Git."""
import argparse
import os
from pathlib import Path
import subprocess
from generate_secrets import generate

ROOT = Path(__file__).resolve().parents[1]

def prepare():
    if not (ROOT / '.env').exists():
        values = generate()
        template = (ROOT / '.env.example').read_text(encoding='utf-8')
        lines = []
        for line in template.splitlines():
            key = line.split('=', 1)[0]
            lines.append(key + '=' + values[key] if key in values else line)
        (ROOT / '.env').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    values = {}
    for line in (ROOT / '.env').read_text(encoding='utf-8-sig').splitlines():
        if line.strip() and not line.lstrip().startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip()
    if len(values.get('EDR_API_KEY', '')) < 32:
        raise ValueError('Set a valid EDR_API_KEY in .env before starting')
    destination = ROOT / 'credentials.txt'
    contents = ('LOCAL ONLY - DO NOT UPLOAD\n'
                'Dashboard: http://localhost:5000\n'
                'Initial username: admin\n'
                'Initial password: change-me-now\n'
                'If you changed the password, the current password is not recoverable here.\n'
                'Agent server: 127.0.0.1 (same computer only)\n'
                'Agent port: 5000\n'
                'Agent TLS: false (localhost lab only)\n'
                'EDR_API_KEY=' + values['EDR_API_KEY'] + '\n')
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(contents)
    if os.name != 'nt':
        destination.chmod(0o600)
        (ROOT / '.env').chmod(0o600)
    print('Saved local credentials.txt; secrets were not printed.')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    prepare()
    if not args.prepare_only:
        subprocess.run(['docker', 'compose', 'up', '--build', '-d'], cwd=ROOT, check=True)
        print('Open http://localhost:5000 and sign in. See credentials.txt.')

if __name__ == '__main__':
    main()
