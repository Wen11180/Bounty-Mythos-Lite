# listmonk campaign API source facts (v6.2.0)

## Endpoint
- GET/PUT/DELETE campaign by id via cmd/campaigns.go handlers
- Local modeling route: /local/listmonk/api/campaigns/{id}

## Read path (GetCampaign)
1. id := getID(c)
2. checkCampaignPerm(auth.PermTypeGet, id, c) BEFORE body load for authorization decision
3. core.GetCampaign(id, "", "") then JSON

## checkCampaignPerm model
1. user := auth.GetUser(c)
2. If PermTypeGet and user.HasPerm(campaigns:get_all) -> allow
3. If manage and user.HasPerm(campaigns:manage_all) -> allow
4. Else GetPermittedLists(get|manage); if not blanket list all:
   - core.CampaignHasLists(id, permittedListIDs) must be true
   - else HTTP 403 permissionDenied

## CampaignHasLists
- SQL check that campaign is attached to at least one of the permitted list IDs
- Fail closed when not overlapping

## Super admin
- UserRoleID SuperAdminRoleID short-circuits HasPerm / GetPermittedLists

## Security contact
- SECURITY.md points to listmonk.app docs security-reports before filing