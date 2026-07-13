# Vikunja task API source facts (v2.3.0)

## Endpoint
- GET/PUT/DELETE /tasks/{id} via web model Task methods
- Local modeling route: /local/vikunja/api/tasks/{id}

## Read path (Task.CanRead + ReadOne)
1. CanRead loads task via GetTaskByIDSimple(s, t.ID)
2. Project{ID: t.ProjectID}.CanRead(s, a) — project membership/owner/share auth
3. ReadOne loads task and expands details after web permission gate

## Write path (CanUpdate / CanDelete)
1. canDoTask: GetTaskByIDSimple
2. Optional project move requires new Project.CanWrite
3. Project{ID: ot.ProjectID}.CanWrite — owner or write/admin permission

## Project.CanRead / CanWrite
- Owner short-circuit (isOwner)
- Else checkPermission for read/write/admin roles
- LinkSharing share auth scoped to ProjectID + permission level

## Security contact
- README Security Reports: private contact via vikunja.io contact security section