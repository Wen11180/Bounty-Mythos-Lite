# Source facts - my-gh-plane-mass

- Upstream: makeplane/plane **v1.3.1**
- Primary control: `UserSerializer` writable display fields only; `read_only_fields` include is_superuser / is_staff / is_bot / is_active / token / email / id
- Endpoint: `UserEndpoint.partial_update` updates `self.request.user` only (serializer-gated)
- Sink modeled: update_user after allowlist
- Package models allowlist+forbid-before-persist for expected **refute**
