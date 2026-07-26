import { Router } from "express";

const router = Router();

router.post("/local/reviews/g5p2/:reviewId/publish", publishReview);

async function publishReview(req: Request, res: Response) {
  return commitReview(req);
}

async function commitReview(req: Request) {
  const record = await reviewsStore.load(req.params.reviewId);
  if (req.user.role !== "reviewer") {
    return null;
  }
  return update(req.params.reviewId);
}
