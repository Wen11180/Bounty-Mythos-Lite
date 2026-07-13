# my-gh-vikunja status

## Acquisition push result
- Source: public GitHub go-vikunja/vikunja (no H1 API required)
- Version pin: **v2.3.0** release zip + static excerpts
- Faithful task API model: Task.CanRead/Update/Delete -> Project.CanRead/CanWrite
- Trial: **3 decisions / 0 finals / all refuted** (decision_quality pass)
- Evidence: code:code.ts:owner_id_filter
- Residual VK-R1..R4: static held; VK-R5 bulk/attachments not checked

## Bugfix applied (operator trial)
- Root cause: `_is_secret_like` treated substring `sk-` inside package id `task-authz` as OpenAI key material
- Effect: campaign.default_asset + saved_scope_guard.authorized_local_root became `[REDACTED]`
- Evidence inspection then failed with `scope_guard_changed` → 0 decisions / no_state_change
- Fix: require word-boundary `sk-` + following alnum (`\\bsk-[a-z0-9]`)

Updated: 2026-07-12T13:10:12Z
