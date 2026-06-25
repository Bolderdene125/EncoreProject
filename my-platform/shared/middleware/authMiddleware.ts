import { authHandler } from "encore.dev/auth";
import { APIError, Header, Gateway } from "encore.dev/api";
import jwt from "jsonwebtoken";

interface AuthParams {
  authorization: Header<"Authorization">;
}

export interface AuthData {
  userID:       string;
  email:        string;
  role:         string;
  tokenExpiresAt: string;
  secondsLeft:  string;
  isExpiringSoon: string;
}

export const myAuthHandler = authHandler<AuthParams, AuthData>(
  async (params) => {
    const authHeader = params.authorization;

    if (!authHeader?.startsWith("Bearer ")) {
      throw APIError.unauthenticated("Authorization header байхгүй байна");
    }

    const token = authHeader.slice(7);

    try {
      const payload = jwt.verify(
        token,
        process.env.JWT_ACCESS_SECRET ?? "dev-secret-change-in-production"
      ) as {
        userId:    string;
        email:     string;
        role:      string;
        tokenType: string;
        exp:       number;
      };

      if (payload.tokenType !== "access") {
        throw APIError.unauthenticated("Access token шаардлагатай");
      }

      const now        = Math.floor(Date.now() / 1000);
      const secondsLeft = payload.exp - now;

      return {
        userID:     payload.userId,
        email:      payload.email,
        role:       payload.role,
        tokenExpiresAt: payload.exp.toString(),
        secondsLeft:   secondsLeft.toString(),
        isExpiringSoon: (secondsLeft < 300).toString(),
      };

    } catch (err: any) {
      if (err.name === "TokenExpiredError") {
        throw APIError.unauthenticated(
          "Token хугацаа дууссан байна. Refresh token ашиглан шинэчлэнэ үү."
        );
      }
      if (err instanceof APIError) throw err;
      throw APIError.unauthenticated("Token хүчингүй байна");
    }
  }
);

export const gateway = new Gateway({
  authHandler: myAuthHandler,
});