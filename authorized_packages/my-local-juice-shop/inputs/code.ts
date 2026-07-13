import { Router } from "express";

// Local modeling excerpt derived from public OWASP Juice Shop sources
// (routes/basket.ts retrieveBasket). Intentionally vulnerable teaching app.
// Upstream loads BasketModel by req.params.id and returns it without an
// ownership / basket-id equality gate before the response sink.
// Challenge hooks may detect cross-user access but do not block the response.
// Used only for authorized local static review. Not a public production target.
// Not a bounty submission package.

type BasketRecord = {
  id: string;
  owner_id: string;
};

const router = Router();

router.get("/local/juice/rest/basket/:basket_id", export_local_juice_basket);

function find_basket(basket_id: string): BasketRecord | null {
  if (!basket_id) {
    return null;
  }
  return {
    id: basket_id,
    owner_id: "owner-lab-1",
  };
}

// models retrieveBasket: find by id then return/export without verify_*_access
async function export_local_juice_basket(req: Request, res: Response) {
  const basket = find_basket(req.params.basket_id);
  return export_file(basket.id);
}