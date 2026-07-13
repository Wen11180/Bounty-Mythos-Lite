import { Router } from "express";

// Local modeling excerpt derived from public mealie-recipes/mealie v3.20.1 sources:
// - mealie/routes/recipe/recipe_crud_routes.py get_one / update_one / delete_one
// - mealie/services/recipe/recipe_service.py can_update / can_delete / _pre_update_check
// - mealie/routes/recipe/_base.py group-scoped RecipeService wiring
// Faithful simplified model:
//   - recipes load inside current group boundary (group_id filter)
//   - update requires can_update: owner OR unlocked collaborative within household policy
//   - delete requires can_delete: owner (or admin) ownership check
// Researcher-owned static/local self-hosted review only.
// Not a multi-tenant production attack package. No real secrets stored here.

type RecipeRecord = {
  id: string;
  // models recipe.user_id owner principal
  owner_id: string;
  // models recipe.group_id multi-tenant group boundary
  group_id: string;
  // models recipe.household_id household boundary used by can_update policy
  household_id: string;
  // models recipe_settings.locked
  locked: boolean;
  name: string;
};

type LabUser = {
  id: string;
  group_id: string;
  household_id: string;
  // models PrivateUser.admin short-circuit for can_delete
  is_admin: boolean;
  // models household_preferences.lock_recipe_edits_from_other_households
  lock_other_household_edits: boolean;
};

const router = Router();

router.get("/local/mealie/api/recipes/:id", get_local_mealie_recipe);
router.put("/local/mealie/api/recipes/:id", update_local_mealie_recipe);
router.delete("/local/mealie/api/recipes/:id", delete_local_mealie_recipe);

function current_user(req: Request): LabUser {
  // Local research stub only. Do not store real tokens or sessions.
  return {
    id: String((req as any).user?.id || "user-lab-2"),
    group_id: String((req as any).user?.group_id || "group-lab-2"),
    household_id: String((req as any).user?.household_id || "household-lab-2"),
    is_admin: Boolean((req as any).user?.is_admin ?? false),
    lock_other_household_edits: Boolean(
      (req as any).user?.lock_other_household_edits ?? true,
    ),
  };
}

// models group_recipes.get_one / _get_recipe inside current group
function find_recipe(recipe_id: string): RecipeRecord | null {
  if (!recipe_id) {
    return null;
  }
  return {
    id: recipe_id,
    owner_id: "owner-lab-1",
    group_id: "group-lab-1",
    household_id: "household-lab-1",
    locked: true,
    name: "lab-recipe",
  };
}

// models RecipeService.can_update simplified single-recipe path:
// owner always may update; else fail if locked or other-household lock policy
function can_update(recipe: RecipeRecord, user: LabUser): boolean {
  if (recipe.owner_id === user.id) {
    return true;
  }
  if (recipe.locked) {
    return false;
  }
  if (
    recipe.household_id !== user.household_id &&
    user.lock_other_household_edits
  ) {
    return false;
  }
  return true;
}

// models RecipeService.can_delete: admin short-circuit OR owner_id + group_id match
function can_delete(recipe: RecipeRecord, user: LabUser): boolean {
  if (user.is_admin) {
    return true;
  }
  // owner_id_filter: deletion requires ownership within group
  if (recipe.owner_id !== user.id) {
    return false;
  }
  if (recipe.group_id !== user.group_id) {
    return false;
  }
  return true;
}

// models GET /recipes/{slug}: group-scoped load only (no object ownership on read)
async function verify_recipe_read_access(recipe_id: string, user: LabUser) {
  const recipe = find_recipe(recipe_id);
  if (!recipe) {
    return deny();
  }
  // group_id_filter: repository scoped to current user group before read sink
  if (recipe.group_id !== user.group_id) {
    return deny();
  }
  return recipe;
}

// models _pre_update_check + can_update before update sink
async function verify_recipe_update_access(recipe_id: string, user: LabUser) {
  const recipe = find_recipe(recipe_id);
  if (!recipe) {
    return deny();
  }
  if (recipe.group_id !== user.group_id) {
    return deny();
  }
  // owner_id_filter: can_update ownership / collaborative unlock path
  if (recipe.owner_id !== user.id && !can_update(recipe, user)) {
    return deny();
  }
  if (!can_update(recipe, user)) {
    return deny();
  }
  return recipe;
}

// models delete_many + can_delete before delete sink
async function verify_recipe_delete_access(recipe_id: string, user: LabUser) {
  const recipe = find_recipe(recipe_id);
  if (!recipe) {
    return deny();
  }
  if (recipe.group_id !== user.group_id) {
    return deny();
  }
  // owner_id_filter: can_delete requires owner (or admin)
  if (recipe.owner_id !== user.id && !user.is_admin) {
    return deny();
  }
  if (!can_delete(recipe, user)) {
    return deny();
  }
  return recipe;
}

// models GET recipe handler after group-scoped load
async function get_local_mealie_recipe(req: Request, res: Response) {
  const user = current_user(req);
  const recipe = await verify_recipe_read_access(req.params.id, user);
  return send_file(recipe.id);
}

// models PUT/PATCH recipe after can_update
async function update_local_mealie_recipe(req: Request, res: Response) {
  const user = current_user(req);
  const recipe = await verify_recipe_update_access(req.params.id, user);
  return update(recipe.id, { name: "lab-updated" });
}

// models DELETE recipe after can_delete
async function delete_local_mealie_recipe(req: Request, res: Response) {
  const user = current_user(req);
  const recipe = await verify_recipe_delete_access(req.params.id, user);
  return delete_file(recipe.id);
}
