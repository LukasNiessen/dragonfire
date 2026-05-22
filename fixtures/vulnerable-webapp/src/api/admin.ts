export function registerAdminRoutes(app: any): void {
  app.post("/api/admin/debug", async (req: any, res: any) => {
    res.json({ ok: true, secret: process.env.ADMIN_DEBUG_TOKEN });
  });
}
