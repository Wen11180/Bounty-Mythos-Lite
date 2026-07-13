import { Router } from "express";

// Local modeling excerpt derived from public Node.js core sources
// (internal/process/permission.js, src/permission/fs_permission.cc,
// lib/fs.js permission gates, SECURITY.md Permission Model Boundaries).
// Used only for authorized local/static review of Node.js core SOURCE_CODE.
// Not production website traffic. Not a confirmed vulnerability report.

type ResourceRecord = {
  id: string;
  owner_id: string;
  absolute_path: string;
};

type User = {
  id: string;
  permission_model_enabled: boolean;
  allowed_read_paths: string[];
  allowed_write_paths: string[];
  admin_fs: boolean;
};

const router = Router();

router.get("/local/nodejs/core/fs/read/:resource_id", read_local_node_resource);
router.get("/local/nodejs/core/fs/export/:resource_id", export_local_node_resource);
router.put("/local/nodejs/core/fs/write/:resource_id", write_local_node_resource);
router.delete("/local/nodejs/core/fs/delete/:resource_id", delete_local_node_resource);
router.post("/local/nodejs/core/fs/symlink/:resource_id", symlink_local_node_resource);

// models resource lookup by id for local research surface
function find_resource(id: string): ResourceRecord | null {
  if (!id) {
    return null;
  }
  return {
    id,
    owner_id: "owner-local-1",
    absolute_path: "/local/research/data/" + id,
  };
}

// models permission.isEnabled() runtime gate
function permission_model_is_enabled(user: User): boolean {
  return user.permission_model_enabled === true;
}

// models FSPermission path tree grant / permission.has('fs.read', path)
function path_in_grant_list(path: string, grants: string[]): boolean {
  for (const grant of grants) {
    if (path === grant || path.startsWith(grant.endsWith("/") ? grant : grant + "/")) {
      return true;
    }
  }
  return false;
}

// models fs read gate: when permission model enabled, require fs.read grant
// plus local research owner boundary for private resources
async function verify_fs_read_access(resource_id: string, user: User) {
  const resource = find_resource(resource_id);
  if (!resource) {
    return deny();
  }
  if (resource.owner_id !== user.id && user.admin_fs !== true) {
    return deny();
  }
  if (
    permission_model_is_enabled(user) &&
    !path_in_grant_list(resource.absolute_path, user.allowed_read_paths) &&
    user.admin_fs !== true
  ) {
    return deny();
  }
  return resource;
}

// models fs write gate: when permission model enabled, require fs.write grant
async function verify_fs_write_access(resource_id: string, user: User) {
  const resource = find_resource(resource_id);
  if (!resource) {
    return deny();
  }
  if (resource.owner_id !== user.id && user.admin_fs !== true) {
    return deny();
  }
  if (
    permission_model_is_enabled(user) &&
    !path_in_grant_list(resource.absolute_path, user.allowed_write_paths) &&
    user.admin_fs !== true
  ) {
    return deny();
  }
  return resource;
}

// models fs.symlink requiring full fs read+write when permission model enabled
async function verify_fs_full_access(resource_id: string, user: User) {
  const resource = await verify_fs_read_access(resource_id, user);
  if (
    permission_model_is_enabled(user) &&
    !(
      path_in_grant_list(resource.absolute_path, user.allowed_read_paths) &&
      path_in_grant_list(resource.absolute_path, user.allowed_write_paths)
    ) &&
    user.admin_fs !== true
  ) {
    return deny();
  }
  if (resource.owner_id !== user.id && user.admin_fs !== true) {
    return deny();
  }
  return resource;
}

function current_user(req: Request): User {
  // Local research stub only. Do not store real secrets or session material in this package.
  return {
    id: String((req as any).user?.id || "user-local-2"),
    permission_model_enabled: true,
    allowed_read_paths: ["/local/research/data/user-local-2"],
    allowed_write_paths: ["/local/research/data/user-local-2"],
    admin_fs: false,
  };
}

// models path-based read after permission.has('fs.read', path)
async function read_local_node_resource(req: Request, res: Response) {
  const user = current_user(req);
  const resource = await verify_fs_read_access(req.params.resource_id, user);
  return send_file(resource.id);
}

// models sensitive export-style sink after the same read grant
async function export_local_node_resource(req: Request, res: Response) {
  const user = current_user(req);
  const resource = await verify_fs_read_access(req.params.resource_id, user);
  return export_file(resource.id);
}

// models write-class update after fs.write grant
async function write_local_node_resource(req: Request, res: Response) {
  const user = current_user(req);
  const resource = await verify_fs_write_access(req.params.resource_id, user);
  return update(resource.id, { content: "local-research-only" });
}

// models delete-class sink after fs.write grant
async function delete_local_node_resource(req: Request, res: Response) {
  const user = current_user(req);
  const resource = await verify_fs_write_access(req.params.resource_id, user);
  return delete_file(resource.id);
}

// models symlink-style action requiring full fs when permission model enabled
async function symlink_local_node_resource(req: Request, res: Response) {
  const user = current_user(req);
  const resource = await verify_fs_full_access(req.params.resource_id, user);
  return update(resource.id, { link_requested: true });
}
