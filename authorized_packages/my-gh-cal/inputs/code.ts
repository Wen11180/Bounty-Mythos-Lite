import { Router } from "express";

// Local modeling excerpt derived from public calcom/cal.com v6.2.0 sources:
// - packages/features/bookings/services/BookingAccessService.ts
// - packages/trpc/server/routers/viewer/bookings/confirm.handler.ts
// - packages/trpc/server/routers/viewer/bookings/editLocation.handler.ts
// Faithful simplified model of doesUserIdHaveAccessToBooking:
//   1. Organizer: booking.userId (owner_id) === user.id
//   2. Host: multi-host / eventType users assignment
//   3. Team/org admin residual: group membership + admin flag
// Fail closed: deny() when none of the access paths hold.
// Note: cached PermissionCheckService stubs that always return true are NOT product authz;
// this model uses explicit organizer/host/admin gates only.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type BookingRecord = {
  id: string;
  // models Booking.userId (organizer)
  owner_id: string;
  // models eventType.teamId membership scope (optional team booking)
  group_id: string | null;
  // models multi-host user ids on eventType.hosts / eventType.users
  host_ids: string[];
  title: string;
  location: string;
};

type LabUser = {
  id: string;
  // models team/org membership id when checking team booking admin residual
  group_id: string;
  // models MembershipRole OWNER/ADMIN for booking.readTeamBookings fallback
  has_team_admin: boolean;
  // models being listed as host/user on the event type
  is_host: boolean;
};

const router = Router();

router.get(
  "/local/cal/api/bookings/:id",
  get_local_cal_booking,
);
router.post(
  "/local/cal/api/bookings/:id/confirm",
  confirm_local_cal_booking,
);
router.patch(
  "/local/cal/api/bookings/:id/location",
  edit_local_cal_booking_location,
);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    group_id: String((req as any).user?.group_id || "team-lab-2"),
    has_team_admin: Boolean((req as any).user?.has_team_admin ?? false),
    is_host: Boolean((req as any).user?.is_host ?? false),
  };
}

// models BookingRepository findByIdIncludeEventType
function find_booking(booking_id: string): BookingRecord | null {
  if (!booking_id) {
    return null;
  }
  return {
    id: booking_id,
    owner_id: "owner-lab-1",
    group_id: "team-lab-1",
    host_ids: ["owner-lab-1", "host-lab-3"],
    title: "lab-booking",
    location: "lab-room",
  };
}

// models Case 1: userId === booking.userId (organizer)
function is_organizer(booking: BookingRecord, user: LabUser): boolean {
  // owner_id_filter: Booking.userId short-circuit
  return booking.owner_id === user.id;
}

// models Case 2: isUserAHost (eventType hosts/users + organizer)
function is_booking_host(booking: BookingRecord, user: LabUser): boolean {
  if (booking.host_ids.includes(user.id)) {
    return true;
  }
  // session flag used only when lab harness injects host assignment
  return user.is_host && booking.host_ids.length > 0;
}

// models Case 3/4/5 simplified: team/org admin residual for team bookings
function is_team_admin_of_booking(booking: BookingRecord, user: LabUser): boolean {
  if (!booking.group_id) {
    return false;
  }
  // group_id_filter: must match eventType.teamId / org team scope
  if (booking.group_id !== user.group_id) {
    return false;
  }
  // fallbackRoles OWNER/ADMIN for booking.readTeamBookings
  return user.has_team_admin;
}

// models BookingAccessService.doesUserIdHaveAccessToBooking
async function verify_booking_access(
  booking_id: string,
  user: LabUser,
) {
  const booking = find_booking(booking_id);
  if (!booking) {
    return deny();
  }
  // Case 1: organizer
  if (is_organizer(booking, user)) {
    return booking;
  }
  // Case 2: multi-host
  if (is_booking_host(booking, user)) {
    return booking;
  }
  // Case 3+: team/org admin residual
  if (is_team_admin_of_booking(booking, user)) {
    return booking;
  }
  // Fail closed — matches UNAUTHORIZED when access denied
  return deny();
}

// models viewer.bookings access path (read)
async function get_local_cal_booking(req: Request, res: Response) {
  const user = current_user(req);
  const booking = await verify_booking_access(req.params.id, user);
  return send_file(booking.id);
}

// models confirm.handler doesUserIdHaveAccessToBooking before confirm
async function confirm_local_cal_booking(req: Request, res: Response) {
  const user = current_user(req);
  const booking = await verify_booking_access(req.params.id, user);
  return update(booking.id, { status: "ACCEPTED" });
}

// models editLocation.handler access gate before location mutation
async function edit_local_cal_booking_location(req: Request, res: Response) {
  const user = current_user(req);
  const booking = await verify_booking_access(req.params.id, user);
  return update(booking.id, { location: "lab-updated-location" });
}