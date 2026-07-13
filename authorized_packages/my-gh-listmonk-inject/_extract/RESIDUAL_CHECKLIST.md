# Residual checklist — my-gh-listmonk-inject (optional)

Static package trial expected **refute** (makeSearchString present before run_sql).

| ID | Question | Static status |
| --- | --- | --- |
| LM-INJ-R1 | makeSearchString runs before QueryCampaigns SQL? | **held** (core.go) |
| LM-INJ-R2 | Search reaches SQL only as bound param $4? | **held** (campaigns.sql) |
| LM-INJ-R3 | Empty search short-circuits to no-op filter? | **held** (`$4 = '' OR ...`) |
| LM-INJ-R4 | orderBy restricted to allowlist fields? | **held** (strSliceContains) |
| LM-INJ-R5 | Other query builders (lists/subscribers) share same sanitizer? | **held_documented** |
| LM-INJ-R6 | Any raw string-concat SQL for user search residual? | **held_documented** (parameterized path) |

Live residual: researcher-owned loopback only; no destructive SQL.
