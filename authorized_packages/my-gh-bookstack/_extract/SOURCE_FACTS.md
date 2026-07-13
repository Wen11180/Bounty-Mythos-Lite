# BookStack page API source facts (v26.05.2)

## Endpoint
- GET/PUT/DELETE /api/pages/{id} via PageApiController

## Read path
1. PageApiController::read()
2. $this->queries->findVisibleByIdOrFail()
3. PageQueries::findVisibleById uses Page::query()->scopes('visible')->find()
4. Page::scopeVisible applies draft restriction + PermissionApplicator::restrictEntityQuery
5. Invisible pages throw NotFoundException (fail closed / no content leak via this path)

## Update path
1. indVisibleByIdOrFail() first
2. checkOwnablePermission(Permission::PageUpdate, ) via userCan(, )
3. Move to new parent also requires visible parent + PageDelete on current page

## Delete path
1. indVisibleByIdOrFail()
2. checkOwnablePermission(Permission::PageDelete, )

## Joint permissions model
- estrictEntityQuery joins joint_permissions for current user role ids
- status IN (1,3) or (owner_id = current user AND status != 2)

## Security contact
- SECURITY.md (.forgejo): contact lead maintainer Dan Brown via bookstackapp.com/links/contact/
- Supported: latest version only