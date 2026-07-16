# Black-box HAR golden packages

Dual-role HAR fixtures for the black-box local-lab quality gate.

| Package | Lab mode | Expected |
| --- | --- | --- |
| `retain_bola_widgets` | `bola` | `cross_account_object_swap` retained |
| `retain_lower_role_widgets` | `bola` | `lower_role_replay` retained |
| `retain_unauth_widgets` | `bola` | `unauthenticated_read_only_replay` retained |
| `retain_multi_family_bola` | `bola` | three core families retained in Top-N |
| `retain_parent_child_bola` | `bola` | `owned_parent_child_swap` retained |
| `retain_state_transition_bola` | `bola` | `reversible_out_of_order_state_transition` retained |
| `refute_guarded_widgets` | `guarded` | `cross_account_object_swap` suppressed |
| `refute_lower_role_guarded_widgets` | `guarded` | `lower_role_replay` suppressed |
| `refute_unauth_guarded_widgets` | `guarded` | `unauthenticated_read_only_replay` suppressed |
| `refute_shared_widgets` | `shared` | `cross_account_object_swap` **refuted** (intended sharing) |
| `refute_parent_child_guarded` | `guarded` | `owned_parent_child_swap` suppressed (parent binding) |
| `refute_state_transition_rollback` | `rollback_failure` | `reversible_out_of_order_state_transition` suppressed |

HARs intentionally include secrets to prove redaction. Pipeline output must never re-emit them.

Run:

```powershell
cd apps/api
python -m pytest tests/test_black_box_har_golden.py tests/test_black_box_leadership_gate.py -q
python -m app black-box-golden --all --out-dir tmp/bb-golden
python -m app black-box-leadership-gate --out tmp/bb-leadership.json
```

Leadership scoreboard (lab claim scope only): `docs/product/black-box-lab-leadership-scoreboard.md`
