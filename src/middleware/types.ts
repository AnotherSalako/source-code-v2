import { Role } from "@prisma/client";

export interface AuthUser {
  id: string;
  role: Role;
  orgId: string | null;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}
