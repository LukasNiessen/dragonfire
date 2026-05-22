export function registerSafeRoutes(app: any): void {
  app.get("/api/me", requireUser, async (req: any, res: any) => {
    res.json({ id: req.user.id });
  });
}

function requireUser(req: any, res: any, next: any): void {
  if (!req.user) return res.status(401).end();
  return next();
}
