import { Role } from "@prisma/client";

export interface AuthUser {
  id: string;
  role: Role;
  orgId: string | null;
}

// Populated by requireDeviceAuth (src/modules/agents/device-auth.middleware.ts)
// — a signed-request identity, not a User. Never coexists with req.user on
// the same request; agent endpoints and human-facing endpoints are disjoint.
export interface AuthDevice {
  id: string;
  clientId: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
      device?: AuthDevice;
    }
  }
}
