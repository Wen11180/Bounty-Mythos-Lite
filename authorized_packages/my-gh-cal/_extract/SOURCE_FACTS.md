# Cal.com booking API source facts (v6.2.0)

## Endpoint
- viewer.bookings.confirm / editLocation (tRPC) gated by BookingAccessService
- Local modeling routes:
  - GET /local/cal/api/bookings/{id}
  - POST /local/cal/api/bookings/{id}/confirm
  - PATCH /local/cal/api/bookings/{id}/location

## BookingAccessService.doesUserIdHaveAccessToBooking
1. Organizer: userId === booking.userId -> allow
2. Host: isUserAHost from eventType.hosts / eventType.users / booking.user -> allow
3. Team booking: eventType.teamId + permission booking.readTeamBookings (fallback OWNER/ADMIN)
4. Managed parent team admin residual
5. Org/team admin of booking organizer residual
6. Else false (handlers throw UNAUTHORIZED)

## EventType residual (documented, not primary model)
- getEventTypeById -> EventTypeRepository.findById filters by userId OR users.some OR team membership
- createEvent procedure: personal owner/assigned user; team ADMIN/OWNER only

## Security contact
- SECURITY.md: security@cal.com