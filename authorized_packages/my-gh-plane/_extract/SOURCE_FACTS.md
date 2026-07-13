# Plane issue API source facts (v1.3.1)

## Endpoint
- IssueViewSet retrieve / partial_update / destroy under project
- Local modeling route: /local/plane/api/projects/{project_id}/issues/{id}

## allow_permission (permissions/base.py)
1. Optional creator=True: WorkspaceMember active + model.created_by == request.user -> allow
2. PROJECT level: ProjectMember role in allowed_roles for project_id
3. Workspace admin who is also project member: allow regardless of project role (residual note)
4. Else 403 Forbidden

## ROLE enum
- ADMIN = 20, MEMBER = 15, GUEST = 5

## IssueViewSet
- retrieve: ADMIN/MEMBER/GUEST + creator=True
- partial_update: ADMIN/MEMBER + creator=True
- destroy: ADMIN + creator=True

## Security contact
- SECURITY.md: security@plane.so