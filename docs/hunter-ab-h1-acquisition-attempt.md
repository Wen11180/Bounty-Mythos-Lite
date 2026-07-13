# H1 Acquisition Attempt — recheck after replace still blocked

Updated: 2026-07-12T09:36:22Z

## Goal

User said token was replaced. Re-probe once.

## Parse result (redacted)

| Field | Result |
| --- | --- |
| Keyfile present | yes |
| Username | parsed (`shufan`) |
| H1 API key | present, length **44**, source `assignment_line_1` |
| File bytes | 249 |
| Token fingerprint (not secret) | head2=`Pq` tail2=`s=` len=44 |

## Live API result

| Step | Result |
| --- | --- |
| `GET /v1/me` | **HTTP 401** `{"errors":[{"status":401}]}` |
| Program list | **not obtained** |

## Interpretation

Still auth rejection by HackerOne.

## Safety

- Secrets not logged

