"""Copy the frontend into the backend package as static data.

Run before building the pipx wheel or the PyInstaller bundle so the desktop
entry point can serve the UI from inside the package. The target directory is
gitignored: it is a build artifact, not a second copy to maintain.
"""

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'frontend' / 'src'
TARGET = ROOT / 'backend' / 'app' / 'webui'
YARA_SOURCE = ROOT / 'backend' / 'yara_rules'
YARA_TARGET = ROOT / 'backend' / 'app' / 'bundled_yara'


def main() -> int:
    if not (SOURCE / 'index.html').is_file():
        print(f'frontend source not found at {SOURCE}', file=sys.stderr)
        return 1
    if TARGET.exists():
        shutil.rmtree(TARGET)
    shutil.copytree(SOURCE, TARGET)
    count = sum(1 for _ in TARGET.rglob('*') if _.is_file())
    print(f'copied {count} files -> {TARGET}')
    if YARA_SOURCE.is_dir():
        if YARA_TARGET.exists():
            shutil.rmtree(YARA_TARGET)
        shutil.copytree(YARA_SOURCE, YARA_TARGET)
        print(f'copied yara rules -> {YARA_TARGET}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
