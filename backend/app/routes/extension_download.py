
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

router = APIRouter(
    prefix="/api/extension",
    tags=["Browser Extension"],
)

# extension_download.py is in:
# idps/backend/app/routes/
# Three parent levels above routes reaches idps.
PROJECT_ROOT = Path(__file__).resolve().parents[3]
EXTENSION_DIR = PROJECT_ROOT / "extension"

EXCLUDED_DIRS = {
    ".git",
    ".idea",
    ".vscode",
    "__pycache__",
    "node_modules",
    "venv",
    ".venv",
}

EXCLUDED_FILES = {
    ".env",
    ".env.local",
    ".env.production",
    "id_rsa",
    "id_rsa.pub",
}

EXCLUDED_SUFFIXES = {
    ".pyc",
    ".pyo",
}


@router.get("/download")
def download_extension():
    """
    Package the Chrome extension source into a ZIP archive.

    The extension directory must exist beside the backend directory.
    Sensitive environment files and development artifacts are excluded.
    """
    if not EXTENSION_DIR.is_dir():
        raise HTTPException(
            status_code=404,
            detail=(
                "Extension source folder was not found. "
                "Expected the extension directory at the project root."
            ),
        )

    manifest = EXTENSION_DIR / "manifest.json"

    if not manifest.is_file():
        raise HTTPException(
            status_code=404,
            detail="manifest.json is missing from the extension folder.",
        )

    archive_buffer = BytesIO()
    included_files = 0

    try:
        with ZipFile(
            archive_buffer,
            mode="w",
            compression=ZIP_DEFLATED,
        ) as archive:
            for file_path in EXTENSION_DIR.rglob("*"):
                if not file_path.is_file():
                    continue

                relative_path = file_path.relative_to(EXTENSION_DIR)

                # Exclude files located inside unwanted directories.
                if any(
                    part in EXCLUDED_DIRS
                    for part in relative_path.parts
                ):
                    continue

                if file_path.name.lower() in EXCLUDED_FILES:
                    continue

                if file_path.suffix.lower() in EXCLUDED_SUFFIXES:
                    continue

                # Never include symbolic links that might point outside
                # the extension source directory.
                if file_path.is_symlink():
                    continue

                archive.write(
                    file_path,
                    arcname=relative_path.as_posix(),
                )
                included_files += 1

    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail="Could not package the browser extension.",
        ) from exc

    if included_files == 0:
        raise HTTPException(
            status_code=500,
            detail="No extension files were available to package.",
        )

    archive_buffer.seek(0)

    return StreamingResponse(
        archive_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": (
                'attachment; filename="idps-shield-extension.zip"'
            ),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
