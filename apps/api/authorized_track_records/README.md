# Authorized track-record drop directory

Place **redacted** live / human-hour export packages here for automatic attach:

- `authorized_live_outcomes.export.json`
- `human_hour_review_logs.export.json`

Or set:

- `MYTHOS_LIVE_TRACK_RECORD`
- `MYTHOS_HUMAN_HOUR_TRACK_RECORD`
- `MYTHOS_TRACK_RECORD_DIR`

Then:

```powershell
python -m app market-leadership-scoreboard --out tmp/market.json
python -m app delivery-readiness --out tmp/delivery.json
```

## Rules

- Only lawful authorized / private-engagement redacted outcomes
- Never commit secrets, tokens, cookies, or raw user data
- `has_real_*` flips only for `source_kind=authorized_redacted_real` (or `authorized_program_redacted`) with `program_authorization_id` and required fields
- Synthetic demos do **not** close market remaining gaps

Preferred produce path:

```powershell
python -m app prepare-research-session-package --package-root path/to/pkg --human-allow-write
# ... fill redacted real notes after authorized research ...
python -m app capture-research-session-track-record --package-root path/to/pkg --declare-real-package --program-authorization-id AUTH --human-allow-export-write --out-dir tmp/capture-real --publish-drop-dir
```
