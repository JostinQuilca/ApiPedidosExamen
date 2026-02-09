const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser"); // <--- NUEVA LIBRERÍA
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

// =======================================================
// 1. CONFIGURACIÓN DEL TRADUCTOR (MIDDLEWARES)
// =======================================================
// IMPORTANTE: Esto habilita que el servidor entienda JSON.
const corsOptions = {};
if (process.env.CORS_ORIGIN) corsOptions.origin = process.env.CORS_ORIGIN;
app.use(cors(Object.keys(corsOptions).length ? corsOptions : undefined));
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));

// =======================================================
// 2. CONEXIÓN A BASE DE DATOS (NeonDB)
// =======================================================
const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.warn(
    "Warning: DATABASE_URL not set. Configure DATABASE_URL in Render environment variables.",
  );
}

const pool = new Pool({ connectionString });

// =======================================================
// 3. SEGURIDAD (TOKEN)
// =======================================================
const verificarToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(403).json({ error: "No token" });

  const token = authHeader.split(" ")[1];
  if (!token || !token.startsWith("TOKEN_REAL_")) {
    return res.status(401).json({ error: "Token inválido" });
  }
  next();
};

// =======================================================
// 4. RUTAS (ENDPOINTS)
// =======================================================

// --- LOGIN ---
app.post("/auth/login", async (req, res) => {
  // DIAGNÓSTICO: Imprimimos qué llega para ver si body sigue fallando
  console.log("--> Intento de Login recibido.");

  if (!req.body) {
    console.error(
      "ERROR FATAL: req.body es undefined. Body-parser no funcionó.",
    );
    return res.status(500).json({ error: "Error interno: Body undefined" });
  }

  const { email, password } = req.body;
  console.log(`Datos: Email=${email}`);

  try {
    const result = await pool.query("SELECT * FROM usuarios WHERE email = $1", [
      email,
    ]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const dbPass = user.password;
      let valid = false;

      try {
        valid = bcrypt.compareSync(password || "", dbPass || "");
      } catch (e) {
        valid = false;
      }

      // Backwards-compat: if stored password was plain text, accept and re-hash it
      if (!valid && password === dbPass) {
        valid = true;
        try {
          const newHash = bcrypt.hashSync(password, 10);
          await pool.query("UPDATE usuarios SET password = $1 WHERE id = $2", [
            newHash,
            user.id,
          ]);
          console.log(`Rehashed password for user ${user.id}`);
        } catch (e) {
          console.warn("Failed to rehash password:", e);
        }
      }

      if (valid) {
        res.json({
          token: `TOKEN_REAL_${user.id}_XYZ`,
          usuario_id: user.id,
          mensaje: "Login Exitoso",
        });
      } else {
        console.log("Credenciales incorrectas");
        res.status(401).json({ error: "Credenciales incorrectas" });
      }
    } else {
      console.log("Credenciales incorrectas");
      res.status(401).json({ error: "Credenciales incorrectas" });
    }
  } catch (err) {
    console.error("Error SQL:", err);
    res.status(500).json({ error: "Error de servidor" });
  }
});

// --- SINCRONIZAR PEDIDOS ---
app.post("/orders", verificarToken, async (req, res) => {
  const pedidos = req.body;

  if (!req.body || !Array.isArray(pedidos)) {
    return res.status(400).json({ error: "Se esperaba una lista de pedidos" });
  }

  console.log(`Recibiendo ${pedidos.length} pedidos...`);
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    for (const p of pedidos) {
      // Validación para evitar crasheos si faltan datos
      if (!p.cliente) continue;

      await client.query(
        `INSERT INTO pedidos 
                (cliente_nombre, cliente_telefono, cliente_direccion, detalle_pedido, tipo_pago, fecha_registro, latitud, longitud, foto_base64)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          p.cliente,
          p.telefono || "",
          p.direccion || "",
          p.detalle || "Sin detalle",
          p.tipo_pago || "Efectivo",
          p.fecha,
          p.latitud || 0,
          p.longitud || 0,
          p.foto_base64 || "",
        ],
      );
    }

    await client.query("COMMIT");
    res.json({ status: "OK", mensaje: "Sincronizado" });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Error Transacción:", e);
    res.status(500).json({ error: "Error al guardar" });
  } finally {
    client.release();
  }
});

// =======================================================
// 5. INICIAR
// =======================================================
app.get("/health", (req, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor (con Body-Parser) escuchando en puerto ${PORT}`);
});
