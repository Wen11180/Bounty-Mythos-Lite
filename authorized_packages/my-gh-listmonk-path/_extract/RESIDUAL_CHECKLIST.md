# Residual checklist — my-gh-listmonk-path (optional)

Static package trial expected **refute** (filepath Base / makeFilename present before get_blob).

| ID | Question | Static status |
| --- | --- | --- |
| LM-PATH-R1 | GetBlob applies filepath.Base before join/read? | **held** (filesystem.go) |
| LM-PATH-R2 | Upload filenames sanitized via makeFilename? | **held** (utils.go + UploadMedia) |
| LM-PATH-R3 | ServeS3Media path param still hits Base in FS provider? | **held** (GetBlob path) |
| LM-PATH-R4 | Empty/unsafe name fail-closed? | **held** (model deny on empty) |
| LM-PATH-R5 | Alternate providers (S3) path semantics residual? | **held_documented** (provider-specific; static FS model only) |

Live residual: researcher-owned loopback only; no real host file disclosure.