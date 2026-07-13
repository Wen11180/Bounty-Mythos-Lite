# Listmonk media path package (path-traversal family)

Updated: 2026-07-12T16:58:00Z

Package: `authorized_packages/my-gh-listmonk-path`
Package id: `my-gh-listmonk-media-path-lab`
Upstream: knadh/listmonk **v6.2.0**
Risk family: **path_traversal**
Expected disposition: **refute**
Trial: **2/0 refuted** (`docs/hunter-ab-listmonk-path-trial.{json,md}`)

## What this proves
- Second non-authz family beyond SSRF: media path sanitization.
- Engine maps pure file-path sinks (`get_blob` / `read_file`) to `missing_path_validation`.
- Controls `filepath_base` / `makeFilename` refute via `path_validation_check`.
- Complements authz package `my-gh-listmonk` without adding pure authz spam.

## Faithful upstream model
- FS `GetBlob`: `os.ReadFile(join(uploadPath, filepath.Base(url)))`
- Upload: `makeFilename` -> Base before Put
- ServeS3Media path param still hits Base in FS provider

## Residual
See `_extract/RESIDUAL_CHECKLIST.md` LM-PATH-R1..R5.

## Do not
- Attack third-party listmonk hosts
- Treat refute package as confirmed vuln
- Store secrets / real user data