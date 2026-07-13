# Residual checklist — my-gh-paperless-path (optional)

Static package trial expected **refute** (sanitize_filename / PurePath.name present before read_file).

| ID | Question | Static status |
| --- | --- | --- |
| PL-PATH-R1 | generate_filename applies pathvalidate.sanitize_filename to title/tags/correspondent? | **held** (file_handling.py) |
| PL-PATH-R2 | original_filename uses PurePath(...).name (no path components)? | **held** (file_handling.py) |
| PL-PATH-R3 | source_path joins ORIGINALS_DIR with relative fname then resolve? | **held** (models.py) |
| PL-PATH-R4 | Empty/unsafe name fail-closed in model? | **held** (model deny on empty) |
| PL-PATH-R5 | Custom FILENAME_FORMAT / storage_path residual semantics? | **held_documented** (format-specific; static sanitize model only) |

Live residual: researcher-owned loopback only; no real host file disclosure.
