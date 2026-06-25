import { SQLDatabase } from "encore.dev/storage/sqldb";

export const db = new SQLDatabase("payment_db", { 
    migrations: "./migrations",
});
