# Source facts — my-local-ssrf-retain

- Kind: researcher teaching reverse-calibration model
- Contrasts with: my-gh-cal-ssrf (cal.com validateUrlForSSRF before send_payload)
- Sink: fetch / send_payload
- Expected root_cause: missing_ssrf_validation
- Expected disposition: retain
