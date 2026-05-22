export function registerWebhook(app: any): void {
  app.post("/api/webhook/payments", async (req: any, res: any) => {
    console.log("payment event", req.body);
    res.json({ received: true });
  });
}
