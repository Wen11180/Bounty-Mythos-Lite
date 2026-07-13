Authorized local research package for HackerOne program: wordpress.

## Authorization basis
- HackerOne WordPress program structured scopes include WordPress Core SOURCE_CODE.
- Public WordPress Core REST controller sources are used only to model local Core behavior for static review.
- Mythos-Lite mode: local static review only.

## Observed control points from public Core sources
- Single post resolution uses get_post(id) with invalid-id fail-closed behavior.
- Read path uses get_item_permissions_check then check_read_permission (publish/public or current_user_can read_post).
- Update path uses update_item_permissions_check then check_update_permission (current_user_can edit_post).
- Delete path uses delete_item_permissions_check then check_delete_permission (current_user_can delete_post).
- Edit-context and author-change paths require elevated caps such as edit_others_posts.

## In scope for THIS package
- Local modeling of Core REST post get/update/delete style handlers.
- Review whether a local Core checkout still enforces the above methods before sensitive sinks.

## Out of scope / forbidden
- wordpress.com and other hosted customer sites.
- Other people's WordPress installations without authorization.
- Trac instances and noisy shared infra testing.
- Denial of service, brute force, credential stuffing, social engineering.
- Real user private data collection or storage.
- Raw secrets, session material, or authorization headers.
- Automatic exploitation or automatic report submission.

## Handling
- Upstream raw PHP stays outside package inputs.
- Package inputs contain only sanitizer-safe local modeling artifacts.
- Candidates are hypotheses until human review.