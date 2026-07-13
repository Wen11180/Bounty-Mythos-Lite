# Immich asset API source facts (v2.7.5)

## Endpoint
- GET/PUT single asset and bulk DELETE via AssetService + access requireAccess
- Local modeling route: /local/immich/api/assets/{id}

## requireAccess / checkAccess
1. Builds allowed id set via checkOtherAccess (or shared-link path)
2. If requested ids not subset of allowed -> BadRequestException Not found or no access

## AssetRead
- checkOwnerAccess(userId, ids)
- else checkAlbumAccess
- else checkPartnerAccess
- union of allowed ids

## AssetUpdate / AssetDelete
- checkOwnerAccess only (no album/partner write)

## AssetService
- get: requireAccess AssetRead then load asset
- update: requireAccess AssetUpdate then mutate
- deleteAll: requireAccess AssetDelete then soft/hard delete

## Security contact
- SECURITY.md: security@immich.app
