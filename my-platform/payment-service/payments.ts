import { api, APIError } from "encore.dev/api";
import { db } from "./db";
import { getAuthData } from "~encore/auth";

interface Payment {
  id:          string;
  userId:      string;
  amount:      number;
  status:      string;
  description: string;
  createdBy:   string;
  createdAt:   string;
}

interface PaymentReq {
  amount:      number;
  description: string;
}

interface PaymentResp {
  paymentId:    string;
  status:       string;
  message:      string;
  tokenSecondsLeft: number;
}

interface HistoryResp {
  payments:  Payment[];
  total:     number;
  tokenSecondsLeft: number;
}

// POST /payment/pay ========================
export const processPayment = api(
  { method: "POST", path: "/payment/pay", expose: true, auth: true },
  async (req: PaymentReq): Promise<PaymentResp> => {
    const auth = getAuthData()!;

    // 1. Талбар шалгах
    if (!req.description) {
      throw APIError.invalidArgument("Тайлбар шаардлагатай");
    }
    if (req.amount <= 0) {
      throw APIError.invalidArgument("Дүн эерэг тоо байх ёстой");
    }

    // 2. Токен хугацаа шалгах
    const secsLeft = parseInt(auth.secondsLeft);
    if (secsLeft <= 0) {
      throw APIError.unauthenticated("Токен хугацаа дууссан байна");
    }

    // 3. INLINE role шалгах, админ зөвхөн 10000 аас дээш төлбөр хийж болно
    // Энэ бол "hard-typed" inline error handling
    if (req.amount > 10000 && auth.role !== "admin") {
      throw APIError.permissionDenied(
        "10,000-с дээш дүн зөвхөн admin хийж болно"
      );
    }

    // 4. Blacklist шалгах
    const blocked = await db.queryRow<{ user_id: string }>`
      SELECT user_id FROM token_blacklist WHERE user_id = ${auth.userID}
    `;
    if (blocked) {
      throw APIError.permissionDenied("Таны эрх хязгаарлагдсан байна");
    }

    // 5. Төлбөр хадгалах
    const payment = await db.queryRow<{ id: string }>`
      INSERT INTO payments (user_id, amount, status, description, created_by)
      VALUES (${auth.userID}, ${req.amount}, 'completed', ${req.description}, ${auth.email})
      RETURNING id
    `;

    if (!payment) throw APIError.internal("Төлбөр хийхэд алдаа гарлаа");

    return {
      paymentId:        payment.id,
      status:           "completed",
      message:          `${req.amount}₮ төлбөр амжилттай хийгдлээ`,
      tokenSecondsLeft: secsLeft,
    };
  }
);

// GET /payment/history ============================
export const paymentHistory = api(
  { method: "GET", path: "/payment/history", expose: true, auth: true },
  async (): Promise<HistoryResp> => {
    const auth = getAuthData()!;
    const rows: Payment[] = [];

    for await (const row of db.query<Payment>`
      SELECT id, user_id AS "userId", amount, status,
             description, created_by AS "createdBy",
             created_at AS "createdAt"
      FROM   payments
      WHERE  user_id = ${auth.userID}
      ORDER  BY created_at DESC
      LIMIT  20
    `) {
      rows.push(row);
    }

    return {
      payments:         rows,
      total:            rows.length,
      tokenSecondsLeft: parseInt(auth.secondsLeft),
    };
  }
);

// GET /payment/all => Зөвхөн admin=========================
export const allPayments = api(
  { method: "GET", path: "/payment/all", expose: true, auth: true },
  async (): Promise<HistoryResp> => {
    const auth = getAuthData()!;

    // INLINE role шалгалт — admin биш бол татгалзана
    if (auth.role !== "admin") {
      throw APIError.permissionDenied(
        "Энэ хэсэгт зөвхөн admin хандаж болно"
      );
    }

    const rows: Payment[] = [];

    for await (const row of db.query<Payment>`
      SELECT id, user_id AS "userId", amount, status,
             description, created_by AS "createdBy",
             created_at AS "createdAt"
      FROM   payments
      ORDER  BY created_at DESC
      LIMIT  100
    `) {
      rows.push(row);
    }

    return {
      payments:         rows,
      total:            rows.length,
      tokenSecondsLeft: parseInt(auth.secondsLeft),
    };
  }
);