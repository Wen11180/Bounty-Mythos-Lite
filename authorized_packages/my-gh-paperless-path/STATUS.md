# my-gh-paperless-path status

## Acquisition push result
- Source: public GitHub paperless-ngx/paperless-ngx (no H1 API required)
- Version pin: **v2.9.0** + static excerpts (file_handling sanitize + source_path)
- Faithful document path model: sanitize_filename / purepath_name before read_file
- Trial: **2/0 decisions / 0 finals / all refuted** (decision_quality pass)
- Evidence: code:code.ts:sanitize_filename
- Residual PL-PATH-R1..R5: static held / format residual documented

## Product read
Second **non-authz (path traversal)** GitHub package (diversity beyond listmonk-path):
- Exercises file-path sinks (
ead_file) and path_validation_check
- Hunter root_cause: missing_path_validation (not object ownership)
- Complements authz package my-gh-paperless and path package my-gh-listmonk-path
- Not a bounty auto-submit package

Updated: 2026-07-12T20:38:48Z
