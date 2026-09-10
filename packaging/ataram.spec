# PyInstaller spec for the ITgalya Email Analyzer desktop build.
#
# Build (run from the repository root, after scripts/sync_webui.py):
#   pyinstaller --noconfirm --distpath dist --workpath build packaging/ataram.spec
#
# onedir on purpose: single-file executables unpack to temp on every launch
# and trip antivirus heuristics far more often. The whole directory is zipped
# for distribution instead.

import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

backend = os.path.abspath(os.path.join(os.getcwd(), 'backend'))

datas = [
    (os.path.join(backend, 'app', 'data'), 'app/data'),
    (os.path.join(backend, 'app', 'webui'), 'app/webui'),
    (os.path.join(backend, 'yara_rules'), 'yara_rules'),
]
datas += collect_data_files('tldextract')

hiddenimports = (
    collect_submodules('app')
    + collect_submodules('dns')
    + ['waitress', 'backports', 'backports.tarfile']
)

a = Analysis(
    [os.path.join(backend, 'app', 'desktop.py')],
    pathex=[backend],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=['gunicorn', 'pytest', 'mypy', 'ruff'],
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name='ITgalyaEmailAnalyzer',
    console=True,
    icon=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    name='ITgalyaEmailAnalyzer',
)
