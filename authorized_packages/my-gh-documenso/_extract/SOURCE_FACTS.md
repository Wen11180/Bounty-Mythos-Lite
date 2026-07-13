# Documenso document/envelope source facts (v2.14.0)

## Endpoint
- tRPC document.get / document.update / document.delete (authenticatedProcedure)
- Local modeling route: /local/documenso/api/documents/{id}

## getEnvelopeWhereInput
1. Validate user belongs to teamId via getTeamById
2. OR access:
   - envelope.userId === userId (owner)
   - envelope.teamId === team.id AND visibility in TEAM_DOCUMENT_VISIBILITY_MAP[role]
   - optional team email path
3. Fail closed: NOT_FOUND / UNAUTHORIZED if query invalid or no match

## TEAM_DOCUMENT_VISIBILITY_MAP
- ADMIN: ADMIN, MANAGER_AND_ABOVE, EVERYONE
- MANAGER: MANAGER_AND_ABOVE, EVERYONE
- MEMBER: EVERYONE

## deleteDocument
- hasDeleteAccess via getEnvelopeWhereInput findFirst
- recipient self-hide path separate (not modeled as hard delete authz bypass)

## Security contact
- SECURITY.md: GitHub private advisory or security@documenso.com