# NocoDB table records API source facts (v2026.06.1)

## Endpoint
- GET/PATCH/DELETE `/api/v2/tables/:modelId/records` via DataTableController
- Local modeling route: /local/nocodb/api/tables/{id}/records

## Auth chain
1. GlobalGuard: JWT / API token / shared base / guest fallback
2. @Acl(permissionName) metadata on handler
3. ExtractIdsMiddleware.canActivate resolves base/table ids and checks rolePermissions
4. Fail closed: NcError.forbidden(generateReadablePermissionErr(...))

## ProjectRoles (base scope)
- VIEWER include: dataList, dataRead, dataCount, ... (no dataUpdate/dataDelete)
- EDITOR include: dataUpdate, dataDelete, dataInsert, bulk ops, ...
- CREATOR / OWNER: broader (exclude-list style for OWNER)

## DataTableController
- dataList: @Acl('dataList')
- dataUpdate: @Acl('dataUpdate')
- dataDelete: @Acl('dataDelete')

## Security contact
- SECURITY.md: security@nocodb.com