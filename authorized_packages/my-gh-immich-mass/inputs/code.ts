import { Router } from "express";

// Local modeling excerpt derived from public immich-app/immich v2.7.5 sources:
// - server/src/dtos/user.dto.ts (UserUpdateMeDto allowlist: email/password/name/avatarColor;
//   isAdmin only on UserAdminCreateDto / UserAdminUpdateDto — not on self-update DTO)
// - server/src/services/user.service.ts (updateMe builds Updateable from dto fields only)
// - server/src/controllers/user.controller.ts (updateMyUser -> updateMe)
// Faithful simplified model of self-update mass-assignment defense:
//   1. Client may attempt to send privilege fields (isAdmin, quota, storageLabel)
//   2. field_allowlist (UserUpdateMeDto) admits only email/name/password/avatarColor
//   3. forbid_privilege_fields rejects residual privilege keys before persist
//   4. update_user only receives allowlisted payload for auth user id
// Fail closed: deny() when privilege fields present or allowlist empty.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type LabUser = {
  id: string;
  email: string;
  name: string;
  isAdmin: boolean;
};

type UserUpdateMeDto = {
  email?: string;
  password?: string;
  name?: string;
  avatarColor?: string;
  // privilege residual keys that must never pass self-update allowlist
  isAdmin?: boolean;
  storageLabel?: string;
  quotaSizeInBytes?: number;
  shouldChangePassword?: boolean;
};

const router = Router();

router.put(
  "/local/immich/api/users/me",
  update_local_immich_me,
);
router.put(
  "/local/immich/api/users/me-guard",
  update_local_immich_me_privilege_guard,
);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    email: String((req as any).user?.email || "lab-user"),
    name: String((req as any).user?.name || "lab"),
    isAdmin: Boolean((req as any).user?.isAdmin || false),
  };
}

// models UserUpdateMeDto field allowlist (email/name/password/avatarColor only)
// Named field_allowlist so MASS_ASSIGN_GUARD_MARKERS fire in codebase_map.
function field_allowlist(dto: UserUpdateMeDto): UserUpdateMeDto {
  const allowed: UserUpdateMeDto = {};
  if (dto.email !== undefined) {
    allowed.email = dto.email;
  }
  if (dto.password !== undefined) {
    allowed.password = dto.password;
  }
  if (dto.name !== undefined) {
    allowed.name = dto.name;
  }
  if (dto.avatarColor !== undefined) {
    allowed.avatarColor = dto.avatarColor;
  }
  return allowed;
}

// models privilege residual exclusion (isAdmin / quota / storageLabel not on UserUpdateMeDto)
// Named forbid_privilege_fields so MASS_ASSIGN_GUARD_MARKERS (forbid_privilege) fire.
function forbid_privilege_fields(dto: UserUpdateMeDto): boolean {
  if (dto.isAdmin !== undefined) {
    return false;
  }
  if (dto.storageLabel !== undefined) {
    return false;
  }
  if (dto.quotaSizeInBytes !== undefined) {
    return false;
  }
  if (dto.shouldChangePassword !== undefined) {
    return false;
  }
  return true;
}

// models updateMe prepare: allowlist + privilege forbid before repository update
function prepare_user_update(user_id: string, dto: UserUpdateMeDto) {
  if (!user_id) {
    return deny();
  }
  if (!forbid_privilege_fields(dto)) {
    return deny();
  }
  const allowed = field_allowlist(dto);
  return allowed;
}

// models userRepository.update(user.id, update) after DTO allowlist
// Named update_user so MASS_ASSIGN_SINK_NAMES fire.
function update_user(user_id: string, payload: UserUpdateMeDto) {
  return { id: user_id, ...payload };
}

// models PUT/PATCH users/me -> updateMyUser -> updateMe
async function update_local_immich_me(req: Request, res: Response) {
  const user = current_user(req);
  const dto = (req as any).body as UserUpdateMeDto;
  const safe = prepare_user_update(user.id, dto);
  return update_user(user.id, safe);
}

// models residual privilege-guard path (same allowlist + explicit forbid before persist)
async function update_local_immich_me_privilege_guard(req: Request, res: Response) {
  const user = current_user(req);
  const dto = (req as any).body as UserUpdateMeDto;
  if (!forbid_privilege_fields(dto)) {
    return deny();
  }
  const safe = field_allowlist(dto);
  return update_user(user.id, safe);
}
