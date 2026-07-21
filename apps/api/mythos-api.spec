from pathlib import Path

api_root = Path.cwd()
migrations_root = api_root / "migrations"
migration_data = []
for source in sorted(migrations_root.rglob("*")):
    relative = source.relative_to(migrations_root)
    if not source.is_file() or "__pycache__" in relative.parts or source.suffix == ".pyc":
        continue
    migration_data.append((str(source), str(Path("migrations") / relative.parent)))

analysis = Analysis(
    [str(api_root / "app" / "desktop_server.py")],
    pathex=[str(api_root)],
    binaries=[],
    datas=[(str(api_root / "alembic.ini"), "."), *migration_data],
    hiddenimports=[
        "app.main",
        "celery.fixups",
        "celery.fixups.django",
        "uvicorn.lifespan.on",
        "uvicorn.loops.auto",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets.auto",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="mythos-api",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)

collect = COLLECT(
    exe,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    name="mythos-api",
)
