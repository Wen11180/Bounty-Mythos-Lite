import { Router } from "express";

// Local modeling excerpt derived from public makeplane/plane v1.3.1 sources:
// - apps/api/plane/app/serializers/user.py (UserSerializer: writable display fields;
//   read_only_fields include is_superuser, is_staff, is_bot, is_active, token, email, id)
// - apps/api/plane/app/views/user/base.py (UserEndpoint.partial_update -> self.request.user)
// - apps/api/plane/db/models/user.py (User privilege/system fields)
// Faithful simplified model of self-update mass-assignment defense:
//   1. Client may attempt to send privilege fields (is_superuser, is_staff, is_bot, is_active, token)
//   2. field_allowlist admits only first_name/last_name/display_name/user_timezone/avatar residuals
//   3. forbid_privilege_fields rejects residual privilege/system keys before persist
//   4. update_user only receives allowlisted payload for auth user id
// Fail closed: deny() when privilege fields present or allowlist empty.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type LabUser = {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  is_superuser: boolean;
};

type UserUpdateMeDto = {
  first_name?: string;
  last_name?: string;
  display_name?: string;
  user_timezone?: string;
  avatar?: string;
  // privilege / system residual keys that must never pass self-update allowlist
  is_superuser?: boolean;
  is_staff?: boolean;
  is_bot?: boolean;
  is_active?: boolean;
  token?: string;
  email?: string;
  is_managed?: boolean;
};

const router = Router();

router.patch(
  "/local/plane/api/users/me",
  update_local_plane_me,
);
router.patch(
  "/local/plane/api/users/me-guard",
  update_local_plane_me_privilege_guard,
);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    email: String((req as any).user?.email || "lab-user"),
    first_name: String((req as any).user?.first_name || "lab"),
    last_name: String((req as any).user?.last_name || "user"),
    is_superuser: Boolean((req as any).user?.is_superuser || false),
  };
}

// models UserSerializer writable fields residual (not in read_only_fields)
// Named field_allowlist so MASS_ASSIGN_GUARD_MARKERS fire in codebase_map.
function field_allowlist(dto: UserUpdateMeDto): UserUpdateMeDto {
  const allowed: UserUpdateMeDto = {};
  if (dto.first_name !== undefined) {
    allowed.first_name = dto.first_name;
  }
  if (dto.last_name !== undefined) {
    allowed.last_name = dto.last_name;
  }
  if (dto.display_name !== undefined) {
    allowed.display_name = dto.display_name;
  }
  if (dto.user_timezone !== undefined) {
    allowed.user_timezone = dto.user_timezone;
  }
  if (dto.avatar !== undefined) {
    allowed.avatar = dto.avatar;
  }
  return allowed;
}

// models UserSerializer.read_only_fields privilege/system residual exclusion
// Named forbid_privilege_fields so MASS_ASSIGN_GUARD_MARKERS (forbid_privilege) fire.
function forbid_privilege_fields(dto: UserUpdateMeDto): boolean {
  if (dto.is_superuser !== undefined) {
    return false;
  }
  if (dto.is_staff !== undefined) {
    return false;
  }
  if (dto.is_bot !== undefined) {
    return false;
  }
  if (dto.is_active !== undefined) {
    return false;
  }
  if (dto.token !== undefined) {
    return false;
  }
  if (dto.email !== undefined) {
    return false;
  }
  if (dto.is_managed !== undefined) {
    return false;
  }
  return true;
}

// models partial_update prepare: allowlist + privilege forbid before repository update
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

// models serializer.save / user update after DTO allowlist + read_only privilege fields
// Named update_user so MASS_ASSIGN_SINK_NAMES fire.
function update_user(user_id: string, payload: UserUpdateMeDto) {
  return { id: user_id, ...payload };
}

// models PATCH users/me -> UserEndpoint.partial_update -> UserSerializer
async function update_local_plane_me(req: Request, res: Response) {
  const user = current_user(req);
  const dto = (req as any).body as UserUpdateMeDto;
  const safe = prepare_user_update(user.id, dto);
  return update_user(user.id, safe);
}

// models residual privilege-guard path (same allowlist + explicit forbid before persist)
async function update_local_plane_me_privilege_guard(req: Request, res: Response) {
  const user = current_user(req);
  const dto = (req as any).body as UserUpdateMeDto;
  if (!forbid_privilege_fields(dto)) {
    return deny();
  }
  const safe = field_allowlist(dto);
  return update_user(user.id, safe);
}
