# Joplin Server item API source facts (v3.7.1)

## Endpoint
- api/items get/delete (and batch) under packages/server/src/routes/api/items.ts
- Local modeling routes:
  - GET/DELETE /local/joplin/api/items/{id}
  - GET /local/joplin/api/shares/{id}

## Item access
1. loadByName(s) joins user_items where user_id = session user (membership scope)
2. items.owner_id identifies creator
3. checkIfAllowed(Delete/Update) for shared items: share.owner_id or accepted shareUser
4. Else ErrorForbidden / not found path

## Share access
- ShareModel checkIfAllowed: user.id !== resource.owner_id -> ErrorForbidden

## Security contact
- SECURITY.md: GitHub private vulnerability reporting with PoC