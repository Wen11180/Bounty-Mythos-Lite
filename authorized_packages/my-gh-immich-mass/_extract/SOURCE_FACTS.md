# Source facts — my-gh-immich-mass

- Upstream: immich-app/immich **v2.7.5**
- Primary control: `UserUpdateMeDto` allowlists email/password/name/avatarColor only
- Privilege fields (isAdmin, storageLabel, quotaSizeInBytes) live on admin DTOs only
- Primary sink: `userRepository.update` / modeled `update_user`
- Self-update route: controller `updateMyUser` -> service `updateMe`
- Package models allowlist-before-persist for expected **refute**
