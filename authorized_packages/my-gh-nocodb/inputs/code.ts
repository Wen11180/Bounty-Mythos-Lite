import { Router } from "express";

// Local modeling excerpt derived from public nocodb/nocodb v2026.06.1 sources:
// - packages/nocodb/src/controllers/data-table.controller.ts
//   GET/PATCH/DELETE /api/v2/tables/:modelId/records with @Acl
// - packages/nocodb/src/utils/acl.ts rolePermissions ProjectRoles
// - packages/nocodb/src/middlewares/extract-ids/extract-ids.middleware.ts
//   ExtractIdsMiddleware.canActivate + generateReadablePermissionErr
// - packages/nocodb/src/guards/global/global.guard.ts GlobalGuard auth
// Faithful simplified model:
//   - Table/base membership: group_id (models base-scoped ProjectRoles membership)
//   - dataList: VIEWER+ (has_data_list)
//   - dataUpdate / dataDelete: EDITOR+ (has_data_update / has_data_delete)
//   - Missing base membership or permission -> deny() / NcError.forbidden
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type TableRecord = {
  id: string;
  // models base id that owns the table (base-scoped ACL)
  group_id: string;
  title: string;
};

type LabUser = {
  id: string;
  // models base membership principal (user's base roles scope)
  group_id: string;
  // models ProjectRoles.VIEWER+ include dataList
  has_data_list: boolean;
  // models ProjectRoles.EDITOR+ include dataUpdate
  has_data_update: boolean;
  // models ProjectRoles.EDITOR+ include dataDelete
  has_data_delete: boolean;
};

const router = Router();

router.get("/local/nocodb/api/tables/:id/records", get_local_nocodb_records);
router.patch("/local/nocodb/api/tables/:id/records", update_local_nocodb_records);
router.delete("/local/nocodb/api/tables/:id/records", delete_local_nocodb_records);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    group_id: String((req as any).user?.group_id || "base-lab-2"),
    has_data_list: Boolean((req as any).user?.has_data_list ?? true),
    has_data_update: Boolean((req as any).user?.has_data_update ?? false),
    has_data_delete: Boolean((req as any).user?.has_data_delete ?? false),
  };
}

// models Model/table resolved under base via ExtractIdsMiddleware
function find_table(table_id: string): TableRecord | null {
  if (!table_id) {
    return null;
  }
  return {
    id: table_id,
    group_id: "base-lab-1",
    title: "lab-table",
  };
}

// models GlobalGuard identity established + base membership before ACL
function has_base_membership(table: TableRecord, user: LabUser): boolean {
  // group_id_filter: user must belong to the same base as the table
  return table.group_id === user.group_id;
}

// models @Acl('dataList') against rolePermissions VIEWER include
async function verify_data_list_access(table_id: string, user: LabUser) {
  const table = find_table(table_id);
  if (!table) {
    return deny();
  }
  // group_id_filter: base membership before permission check
  if (table.group_id !== user.group_id) {
    return deny();
  }
  if (!has_base_membership(table, user)) {
    return deny();
  }
  // role permission: ProjectRoles.VIEWER+ dataList
  if (!user.has_data_list) {
    return deny();
  }
  return table;
}

// models @Acl('dataUpdate') against rolePermissions EDITOR include
async function verify_data_update_access(table_id: string, user: LabUser) {
  const table = find_table(table_id);
  if (!table) {
    return deny();
  }
  // group_id_filter: base membership before permission check
  if (table.group_id !== user.group_id) {
    return deny();
  }
  if (!has_base_membership(table, user)) {
    return deny();
  }
  // role permission: ProjectRoles.EDITOR+ dataUpdate
  if (!user.has_data_update) {
    return deny();
  }
  return table;
}

// models @Acl('dataDelete') against rolePermissions EDITOR include
async function verify_data_delete_access(table_id: string, user: LabUser) {
  const table = find_table(table_id);
  if (!table) {
    return deny();
  }
  // group_id_filter: base membership before permission check
  if (table.group_id !== user.group_id) {
    return deny();
  }
  if (!has_base_membership(table, user)) {
    return deny();
  }
  // role permission: ProjectRoles.EDITOR+ dataDelete
  if (!user.has_data_delete) {
    return deny();
  }
  return table;
}

// models DataTableController.dataList after @Acl('dataList')
async function get_local_nocodb_records(req: Request, res: Response) {
  const user = current_user(req);
  const table = await verify_data_list_access(req.params.id, user);
  return send_file(table.id);
}

// models DataTableController.dataUpdate after @Acl('dataUpdate')
async function update_local_nocodb_records(req: Request, res: Response) {
  const user = current_user(req);
  const table = await verify_data_update_access(req.params.id, user);
  return update(table.id, { title: "lab-updated" });
}

// models DataTableController.dataDelete after @Acl('dataDelete')
async function delete_local_nocodb_records(req: Request, res: Response) {
  const user = current_user(req);
  const table = await verify_data_delete_access(req.params.id, user);
  return delete_file(table.id);
}