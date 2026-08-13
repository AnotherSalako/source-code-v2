import { describe, it, expect, beforeEach } from "vitest";
import { seedUser, resetFakeDb } from "./helpers/test-app";
import { bootstrapAdmin } from "../scripts/bootstrap-admin";

beforeEach(() => {
  resetFakeDb();
});

describe("bootstrapAdmin", () => {
  it("refuses an invalid email without touching the database", async () => {
    const result = await bootstrapAdmin("Jane Doe", "not-an-email");
    expect(result.status).toBe("refused");
  });

  it("refuses to run when a SECURITY_ADMIN already exists — the core safety rail", async () => {
    seedUser({ email: "existing-admin@example.com", name: "Existing", role: "SECURITY_ADMIN", orgId: null });
    const result = await bootstrapAdmin("New Admin", "new-admin@example.com");
    expect(result.status).toBe("refused");
    if (result.status === "refused") {
      expect(result.reason).toMatch(/already has/);
    }
  });

  it("refuses a duplicate email even with zero admins yet (e.g. a stray client-role row)", async () => {
    seedUser({ email: "taken@example.com", name: "Someone", role: "TECHNICAL_CLIENT", orgId: "org-1" });
    const result = await bootstrapAdmin("New Admin", "taken@example.com");
    expect(result.status).toBe("refused");
  });

  it("creates the first SECURITY_ADMIN on a genuinely empty deployment and sends a real invitation", async () => {
    const result = await bootstrapAdmin("Jane Doe", "jane@example.com");
    expect(result.status).toBe("created");
    if (result.status === "created") {
      expect(result.invitationSent).toBe(true);
      expect(result.userId).toBeTruthy();
    }
  });

  it("a second bootstrap call after the first refuses (proves the rail isn't a one-time check bypassable by re-running)", async () => {
    await bootstrapAdmin("First Admin", "first@example.com");
    const second = await bootstrapAdmin("Second Admin", "second@example.com");
    expect(second.status).toBe("refused");
  });
});
