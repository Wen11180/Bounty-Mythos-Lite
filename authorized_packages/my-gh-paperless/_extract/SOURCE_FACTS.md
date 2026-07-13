# paperless-ngx document API source facts (v2.9.0)

## Endpoint
- DocumentViewSet retrieve/update/destroy on documents API
- Local modeling route: /local/paperless/api/documents/{id}

## Object permission model (PaperlessObjectPermissions)
1. If obj.owner is not None:
   - owner (request.user == obj.owner) -> allow
   - else DjangoObjectPermissions / guardian object-level view|change|delete
2. If owner is None -> allow (backwards-compat unowned)

## List filter (ObjectOwnedOrGrantedPermissionsFilter)
- objects with guardian read perms OR owner == request.user OR owner is null

## has_perms_owner_aware
- used by file/preview/notes/share helpers
- True when owner is None OR owner == user OR ObjectPermissionChecker.has_perm

## Security contact
- SECURITY.md: GitHub Security Advisory private report tab
