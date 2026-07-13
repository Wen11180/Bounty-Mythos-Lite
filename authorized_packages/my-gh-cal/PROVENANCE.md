# Provenance

## Why this acquisition is lawful for this project
1. Upstream code is public open source on GitHub: calcom/cal.com.
2. Cal.com publishes SECURITY.md with private security@cal.com reporting.
3. Materials are used for local static modeling / researcher-owned self-hosted review inside Mythos-Lite.
4. No third-party production multi-tenant targeting, no real secrets in package inputs, no automatic submission.

## What was fetched
Public upstream version **v6.2.0** (@calcom/web package.json) source excerpts under _upstream/:
- packages/features/bookings/services/BookingAccessService.ts
- packages/trpc/server/routers/viewer/bookings/confirm.handler.ts
- packages/trpc/server/routers/viewer/bookings/editLocation.handler.ts
- packages/features/eventtypes/lib/getEventTypeById.ts
- packages/features/eventtypes/repositories/eventTypeRepository.ts
- packages/trpc/server/routers/viewer/eventTypes/util.ts
- SECURITY.md

## What enters the hunter
Only inputs/* and package.json.

## Sanitizer
No Authorization headers, no API tokens, no cookies, no real user emails in inputs.