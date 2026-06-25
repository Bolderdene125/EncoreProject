import { api, APIError } from "encore.dev/api";
import { db } from "./db";
import { getAuthData } from "~encore/auth";

interface Vehicle {
  id:     string;
  userId: string;
  make:   string;
  model:  string;
  year:   number;
  plate:  string;
  createdAt: string;
}

interface CreateVehicleReq {
  make:  string;
  model: string;
  year:  number;
  plate: string;
}

interface VehicleListResp {
  vehicles:     Vehicle[];
  total:        number;
  tokenSecondsLeft: number;
}

export const listVehicles = api(
  { method: "GET", path: "/auto/vehicles", expose: true, auth: true },
  async (): Promise<VehicleListResp> => {
    const auth = getAuthData()!;
    const rows: Vehicle[] = [];

    for await (const row of db.query<Vehicle>`
      SELECT id, user_id AS "userId", make, model, year, plate,
             created_at AS "createdAt"
      FROM   vehicles
      WHERE  user_id = ${auth.userID}
      ORDER  BY created_at DESC
    `) {
      rows.push(row);
    }

    return {
      vehicles:         rows,
      total:            rows.length,
      tokenSecondsLeft: parseInt(auth.secondsLeft),
    };
  }
);

export const createVehicle = api(
  { method: "POST", path: "/auto/vehicles", expose: true, auth: true },
  async (req: CreateVehicleReq): Promise<Vehicle> => {
    const auth = getAuthData()!;

    if (!req.make || !req.model || !req.plate) {
      throw APIError.invalidArgument("Бүх талбарыг бөглөнө үү");
    }
    if (req.year < 1900 || req.year > 2030) {
      throw APIError.invalidArgument("Он буруу байна");
    }

    const exists = await db.queryRow<{ id: string }>`
      SELECT id FROM vehicles WHERE plate = ${req.plate}
    `;
    if (exists) {
      throw APIError.alreadyExists("Энэ улсын дугаар аль хэдийн бүртгэгдсэн");
    }

    const vehicle = await db.queryRow<Vehicle>`
      INSERT INTO vehicles (user_id, make, model, year, plate)
      VALUES (${auth.userID}, ${req.make}, ${req.model}, ${req.year}, ${req.plate})
      RETURNING id, user_id AS "userId", make, model, year, plate,
                created_at AS "createdAt"
    `;

    if (!vehicle) throw APIError.internal("Машин үүсгэхэд алдаа гарлаа");
    return vehicle;
  }
);

export const getVehicle = api(
  { method: "GET", path: "/auto/vehicles/:id", expose: true, auth: true },
  async ({ id }: { id: string }): Promise<Vehicle> => {
    const auth = getAuthData()!;

    const vehicle = await db.queryRow<Vehicle>`
      SELECT id, user_id AS "userId", make, model, year, plate,
             created_at AS "createdAt"
      FROM   vehicles
      WHERE  id = ${id}
    `;

    if (!vehicle) throw APIError.notFound("Машин олдсонгүй");

    if (vehicle.userId !== auth.userID && auth.role !== "admin") {
      throw APIError.permissionDenied("Энэ машинд хандах эрхгүй байна");
    }

    return vehicle;
  }
);

export const deleteVehicle = api(
  { method: "DELETE", path: "/auto/vehicles/:id", expose: true, auth: true },
  async ({ id }: { id: string }): Promise<{ deleted: boolean }> => {
    const auth = getAuthData()!;

    const vehicle = await db.queryRow<{ id: string; userId: string }>`
      SELECT id, user_id AS "userId" FROM vehicles WHERE id = ${id}
    `;

    if (!vehicle) throw APIError.notFound("Машин олдсонгүй");

    if (vehicle.userId !== auth.userID && auth.role !== "admin") {
      throw APIError.permissionDenied("Энэ машинг устгах эрхгүй байна");
    }

    await db.exec`DELETE FROM vehicles WHERE id = ${id}`;
    return { deleted: true };
  }
);