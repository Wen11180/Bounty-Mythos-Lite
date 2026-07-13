import { Router } from "express";

// Local modeling excerpt derived from public go-vikunja/vikunja v2.3.0 sources:
// - pkg/models/tasks_permissions.go Task.CanRead / CanUpdate / CanDelete / canDoTask
// - pkg/models/project_permissions.go Project.CanRead / CanWrite (owner or permission)
// - pkg/models/tasks.go Task.ReadOne (load after web CanRead gate)
// Faithful simplified model: task inherits project ownership/write boundary.
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type TaskRecord = {
  id: string;
  project_id: string;
  // models project owner id used by Project.isOwner / CanRead short-circuit
  owner_id: string;
  title: string;
};

type LabUser = {
  id: string;
  // models project membership granting read permission
  can_read_project: boolean;
  // models project write/admin permission
  can_write_project: boolean;
};

const router = Router();

router.get("/local/vikunja/api/tasks/:id", get_local_vikunja_task);
router.put("/local/vikunja/api/tasks/:id", update_local_vikunja_task);
router.delete("/local/vikunja/api/tasks/:id", delete_local_vikunja_task);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    can_read_project: Boolean((req as any).user?.can_read_project ?? false),
    can_write_project: Boolean((req as any).user?.can_write_project ?? false),
  };
}

// models GetTaskByIDSimple
function find_task(task_id: string): TaskRecord | null {
  if (!task_id) {
    return null;
  }
  return {
    id: task_id,
    project_id: "project-lab-1",
    owner_id: "owner-lab-1",
    title: "lab-task",
  };
}

// models Project.CanRead: isOwner OR checkPermission(read|write|admin)
function project_can_read(task: TaskRecord, user: LabUser): boolean {
  if (task.owner_id === user.id) {
    return true;
  }
  return user.can_read_project === true || user.can_write_project === true;
}

// models Project.CanWrite: isOwner OR checkPermission(write|admin)
function project_can_write(task: TaskRecord, user: LabUser): boolean {
  if (task.owner_id === user.id) {
    return true;
  }
  return user.can_write_project === true;
}

// models Task.CanRead -> Project.CanRead after GetTaskByIDSimple
async function verify_task_read_access(task_id: string, user: LabUser) {
  const task = find_task(task_id);
  if (!task) {
    return deny();
  }
  // owner_id_filter: project ownership/permission boundary before read sink
  if (task.owner_id !== user.id && !user.can_read_project && !user.can_write_project) {
    return deny();
  }
  if (!project_can_read(task, user)) {
    return deny();
  }
  return task;
}

// models Task.CanUpdate / canDoTask -> Project.CanWrite
async function verify_task_update_access(task_id: string, user: LabUser) {
  const task = find_task(task_id);
  if (!task) {
    return deny();
  }
  // owner_id_filter: project write boundary before update sink
  if (task.owner_id !== user.id && !user.can_write_project) {
    return deny();
  }
  if (!project_can_write(task, user)) {
    return deny();
  }
  return task;
}

// models Task.CanDelete / canDoTask -> Project.CanWrite
async function verify_task_delete_access(task_id: string, user: LabUser) {
  const task = find_task(task_id);
  if (!task) {
    return deny();
  }
  if (task.owner_id !== user.id && !user.can_write_project) {
    return deny();
  }
  if (!project_can_write(task, user)) {
    return deny();
  }
  return task;
}

// models GET /tasks/{id} after CanRead
async function get_local_vikunja_task(req: Request, res: Response) {
  const user = current_user(req);
  const task = await verify_task_read_access(req.params.id, user);
  return send_file(task.id);
}

// models PUT /tasks/{id} after CanUpdate
async function update_local_vikunja_task(req: Request, res: Response) {
  const user = current_user(req);
  const task = await verify_task_update_access(req.params.id, user);
  return update(task.id, { title: "lab-updated" });
}

// models DELETE /tasks/{id} after CanDelete
async function delete_local_vikunja_task(req: Request, res: Response) {
  const user = current_user(req);
  const task = await verify_task_delete_access(req.params.id, user);
  return delete_file(task.id);
}