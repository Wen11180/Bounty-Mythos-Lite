# my-gh-listmonk-path status

## Acquisition push result
- Source: public GitHub knadh/listmonk (no H1 API required)
- Version pin: **v6.2.0** + static excerpts (filesystem GetBlob + makeFilename)
- Faithful media path model: filepath_base / makeFilename before get_blob
- Trial: **2/0 decisions / 0 finals / all refuted** (decision_quality pass)
- Evidence: code:code.ts:filepath_base / makeFilename
- Residual LM-PATH-R1..R5: static held / provider residual documented

## Product read
Second **non-authz (path traversal)** GitHub package:
- Exercises file-path sinks (`get_blob`) and `path_validation_check`
- Hunter root_cause: `missing_path_validation` (not object ownership)
- Complements authz package `my-gh-listmonk` and SSRF package `my-gh-cal-ssrf`
- Not a bounty auto-submit package

Updated: 2026-07-12T16:58:00Z