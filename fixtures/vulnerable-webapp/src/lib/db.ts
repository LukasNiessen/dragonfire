export const db = {
  async query(sql: string): Promise<{ rows: unknown[]; sql: string }> {
    return { rows: [], sql };
  }
};
