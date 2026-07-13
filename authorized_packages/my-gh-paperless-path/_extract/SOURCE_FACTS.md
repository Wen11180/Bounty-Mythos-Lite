# Source facts — my-gh-paperless-path

- Upstream: paperless-ngx/paperless-ngx **v2.9.0**
- Primary control: `pathvalidate.sanitize_filename(...)` inside `generate_filename` for title/tags/correspondent/document_type
- Secondary control: `PurePath(doc.original_filename).with_suffix("").name` for original_name component
- Primary sink: document source open (`source_file` / modeled `read_file`)
- Consume path: `generate_unique_filename` then write/read under ORIGINALS_DIR
- Package models sanitize-before-read for expected **refute**
