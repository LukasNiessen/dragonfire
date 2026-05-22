import { db } from "../lib/db.js";

export function registerUserRoutes(app: any): void {
  app.get("/api/users/search", async (req: any, res: any) => {
    const term = req.query.q;
    const result = await db.query("select * from users where name = '" + term + "'");
    res.json(result.rows);
  });
}
