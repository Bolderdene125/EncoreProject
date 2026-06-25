import { api, APIError } from "encore.dev/api";
import { db } from "./db";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const ACCESS_SECRET  = process.env.JWT_ACCESS_SECRET  ?? "dev-secret-change-in-production";
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET ?? "dev-refresh-change-in-production";

// Нэвтрэх======================
interface LoginReq {
  email:    string;
  password: string;
}
interface LoginResp {
  accessToken:  string;
  refreshToken: string;
  expiresIn:    number;
  user: {
    id:    string;
    email: string;
    role:  string;
    name:  string;
  };
}

export const login = api(
  { method: "POST", path: "/auto/login", expose: true },
  async (req: LoginReq): Promise<LoginResp> => {

    if (!req.email || !req.password) {
      throw APIError.invalidArgument("И-мэйл болон нууц үг шаардлагатай");
    }

    const user = await db.queryRow<{
      id: string; email: string; password: string; name: string; role: string;
    }>`SELECT id, email, password, name, role FROM users WHERE email = ${req.email}`;

    if (!user) {
      throw APIError.notFound("И-мэйл эсвэл нууц үг буруу байна");
    }

    const valid = await bcrypt.compare(req.password, user.password);
    if (!valid) {
      throw APIError.unauthenticated("И-мэйл эсвэл нууц үг буруу байна");
    }

    const now   = Math.floor(Date.now() / 1000);
    const expIn = 15 * 60;

    const accessToken = jwt.sign(
      { userId: user.id, email: user.email, role: user.role, tokenType: "access", iat: now, exp: now + expIn },
      ACCESS_SECRET
    );

    const refreshToken = jwt.sign(
      { userId: user.id, tokenType: "refresh", iat: now, exp: now + 7 * 24 * 60 * 60 },
      REFRESH_SECRET
    );

    const tokenHash = await bcrypt.hash(refreshToken, 10);
    await db.exec`
      INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
      VALUES (${user.id}, ${tokenHash}, NOW() + INTERVAL '7 days')
    `;

    return {
      accessToken,
      refreshToken,
      expiresIn: expIn,
      user: { id: user.id, email: user.email, role: user.role, name: user.name },
    };
  }
);

// Register hiih====================================
interface RegisterReq {
  email:    string;
  password: string;
  name:     string;
}

export const register = api(
  { method: "POST", path: "/auto/register", expose: true },
  async (req: RegisterReq): Promise<LoginResp> => {

    if (!req.email || !req.password || !req.name) {
      throw APIError.invalidArgument("Бүх талбарыг бөглөнө үү");
    }

    const exists = await db.queryRow<{ id: string }>`
      SELECT id FROM users WHERE email = ${req.email}
    `;
    if (exists) {
      throw APIError.alreadyExists("Энэ и-мэйл аль хэдийн бүртгэгдсэн байна");
    }

    const hashed = await bcrypt.hash(req.password, 12);
    const user = await db.queryRow<{
      id: string; email: string; name: string; role: string;
    }>`
      INSERT INTO users (email, password, name)
      VALUES (${req.email}, ${hashed}, ${req.name})
      RETURNING id, email, name, role
    `;

    if (!user) throw APIError.internal("Бүртгэл үүсгэхэд алдаа гарлаа");

    const now   = Math.floor(Date.now() / 1000);
    const expIn = 15 * 60;

    const accessToken = jwt.sign(
      { userId: user.id, email: user.email, role: user.role, tokenType: "access", iat: now, exp: now + expIn },
      ACCESS_SECRET
    );
    const refreshToken = jwt.sign(
      { userId: user.id, tokenType: "refresh", iat: now, exp: now + 7 * 24 * 60 * 60 },
      REFRESH_SECRET
    );

    const tokenHash = await bcrypt.hash(refreshToken, 10);
    await db.exec`
      INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
      VALUES (${user.id}, ${tokenHash}, NOW() + INTERVAL '7 days')
    `;

    return {
      accessToken,
      refreshToken,
      expiresIn: expIn,
      user: { id: user.id, email: user.email, role: user.role, name: user.name },
    };
  }
);

// Refresh token ==========================
interface RefreshReq  { refreshToken: string }
interface RefreshResp { accessToken: string; expiresIn: number }

export const refresh = api(
  { method: "POST", path: "/auto/refresh", expose: true },
  async (req: RefreshReq): Promise<RefreshResp> => {

    let payload: any;
    try {
      payload = jwt.verify(req.refreshToken, REFRESH_SECRET);
    } catch {
      throw APIError.unauthenticated("Refresh token хүчингүй байна");
    }

    const stored = await db.queryRow<{ token_hash: string }>`
      SELECT token_hash FROM refresh_tokens
      WHERE user_id = ${payload.userId}
        AND revoked  = false
        AND expires_at > NOW()
      ORDER BY created_at DESC LIMIT 1
    `;
    if (!stored) throw APIError.unauthenticated("Refresh token олдсонгүй");

    const valid = await bcrypt.compare(req.refreshToken, stored.token_hash);
    if (!valid) throw APIError.unauthenticated("Refresh token таарахгүй байна");

    const user = await db.queryRow<{ email: string; role: string }>`
      SELECT email, role FROM users WHERE id = ${payload.userId}
    `;
    if (!user) throw APIError.notFound("Хэрэглэгч олдсонгүй");

    const now   = Math.floor(Date.now() / 1000);
    const expIn = 15 * 60;

    const accessToken = jwt.sign(
      { userId: payload.userId, email: user.email, role: user.role, tokenType: "access", iat: now, exp: now + expIn },
      ACCESS_SECRET
    );

    return { accessToken, expiresIn: expIn };
  }
);