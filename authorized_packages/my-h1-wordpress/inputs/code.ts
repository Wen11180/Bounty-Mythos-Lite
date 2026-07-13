import { Router } from "express";

// Local modeling excerpt derived from public WordPress Core REST sources
// (WP_REST_Posts_Controller get_post / get_item_permissions_check /
// check_read_permission / check_update_permission / check_delete_permission).
// Used only for authorized local/static review of WordPress Core source.
// Not wordpress.com production traffic. Not a confirmed vulnerability report.

type PostRecord = {
  id: string;
  owner_id: string;
  status: "publish" | "draft" | "private";
};

type User = {
  id: string;
  can_edit_others_posts: boolean;
};

const router = Router();

router.get("/local/wp/wp-json/wp/v2/posts/:id", get_local_wp_post);
router.get("/local/wp/wp-json/wp/v2/posts/:id/export", export_local_wp_post);
router.put("/local/wp/wp-json/wp/v2/posts/:id", update_local_wp_post);
router.delete("/local/wp/wp-json/wp/v2/posts/:id", delete_local_wp_post);

// models WP_REST_Posts_Controller::get_post
function find_post(id: string): PostRecord | null {
  if (!id) {
    return null;
  }
  return {
    id,
    owner_id: "author-local-1",
    status: "draft",
  };
}

// models check_read_permission: publish/public or current_user_can('read_post')
async function verify_read_post_access(post_id: string, user: User) {
  const post = find_post(post_id);
  if (!post) {
    return deny();
  }
  if (post.status === "publish") {
    return post;
  }
  // private/draft requires ownership-style read_post capability boundary
  if (post.owner_id !== user.id && user.can_edit_others_posts !== true) {
    return deny();
  }
  return post;
}

// models check_update_permission: current_user_can('edit_post', post.ID)
async function verify_update_post_access(post_id: string, user: User) {
  const post = find_post(post_id);
  if (!post) {
    return deny();
  }
  if (post.owner_id !== user.id && user.can_edit_others_posts !== true) {
    return deny();
  }
  return post;
}

// models check_delete_permission: current_user_can('delete_post', post.ID)
async function verify_delete_post_access(post_id: string, user: User) {
  const post = find_post(post_id);
  if (!post) {
    return deny();
  }
  if (post.owner_id !== user.id && user.can_edit_others_posts !== true) {
    return deny();
  }
  return post;
}

function current_user(req: Request): User {
  // Local research stub only. Do not store real secrets or session material in this package.
  return {
    id: String((req as any).user?.id || "user-local-2"),
    can_edit_others_posts: false,
  };
}

// models GET /wp/v2/posts/:id after get_item_permissions_check
async function get_local_wp_post(req: Request, res: Response) {
  const user = current_user(req);
  const post = await verify_read_post_access(req.params.id, user);
  return send_file(post.id);
}

// models local export-style sink after the same read gate
async function export_local_wp_post(req: Request, res: Response) {
  const user = current_user(req);
  const post = await verify_read_post_access(req.params.id, user);
  return export_file(post.id);
}

// models PUT/PATCH update_item after update_item_permissions_check
async function update_local_wp_post(req: Request, res: Response) {
  const user = current_user(req);
  const post = await verify_update_post_access(req.params.id, user);
  return update(post.id, { title: "local-research-only" });
}

// models DELETE delete_item after delete_item_permissions_check
async function delete_local_wp_post(req: Request, res: Response) {
  const user = current_user(req);
  const post = await verify_delete_post_access(req.params.id, user);
  return delete_file(post.id);
}