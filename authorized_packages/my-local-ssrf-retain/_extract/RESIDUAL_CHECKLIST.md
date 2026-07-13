# Residual checklist — my-local-ssrf-retain (teaching)

Static package trial expected **retain** (no validateUrlForSSRF before fetch).

| ID | Question | Static status |
| --- | --- | --- |
| LAB-SSRF-R1 | User-controlled subscriberUrl reaches fetch? | **yes (intentional)** |
| LAB-SSRF-R2 | validateUrlForSSRF / private IP guard present? | **absent (intentional)** |
| LAB-SSRF-R3 | Teaching only; not production bounty? | **held** |

Live residual: none required. Not a public target.
