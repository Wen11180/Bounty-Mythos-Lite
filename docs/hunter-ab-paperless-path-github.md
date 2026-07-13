# Paperless-ngx document path package (path-traversal family)

Updated: 2026-07-12T20:38:48Z

Package: uthorized_packages/my-gh-paperless-path
Package id: my-gh-paperless-doc-path-lab
Upstream: paperless-ngx/paperless-ngx **v2.9.0**
Risk family: **path_traversal**
Expected disposition: **refute**
Trial: **2/0 refuted** (docs/hunter-ab-paperless-path-trial.{json,md})

## What this proves
- Second path-traversal GitHub package (diversity beyond listmonk-path).
- Engine maps file-path sinks (
ead_file) to missing_path_validation.
- Control sanitize_filename (pathvalidate model + PurePath.name) refutes via path_validation_check.
- Complements authz package my-gh-paperless without adding pure authz spam.

## Faithful upstream model
- generate_filename: pathvalidate.sanitize_filename on title/tags/correspondent/document_type
- original_name: PurePath(doc.original_filename).with_suffix("").name
- source_path: (ORIGINALS_DIR / Path(fname)).resolve() after sanitized relative name
- Consumer: generate_unique_filename then write under originals root

## Residual
See _extract/RESIDUAL_CHECKLIST.md PL-PATH-R1..R5.

## Do not
- Attack third-party paperless-ngx hosts
- Treat refute package as confirmed vuln
- Store secrets / real user data
