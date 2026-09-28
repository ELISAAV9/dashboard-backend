import express from "express";
import cors from "cors";
import { createRemoteJWKSet, jwtVerify } from "jose";

const PORT = process.env.PORT || 3000;
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || "http://localhost:8081";
const REALM = process.env.KEYCLOAK_REALM || "cybersecurity";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:5173";

const ISSUER = `${KEYCLOAK_URL}/realms/${REALM}`;
// Keycloak publica aqui sus llaves publicas para verificar la firma del JWT
const JWKS = createRemoteJWKSet(
  new URL(`${ISSUER}/protocol/openid-connect/certs`)
);

const app = express();
app.use(cors({ origin: FRONTEND_ORIGIN }));
app.use(express.json());

// Base de datos "de mentiras": vive en memoria. Un arreglo por usuario.
const itemsPorUsuario = new Map();

// ---------- Middleware de autenticacion ----------
async function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization;

  // 1) El Bearer Token debe existir
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.log(`[${req.method} ${req.path}] SIN token -> 401`);
    return res.status(401).json({ error: "Falta el Bearer Token" });
  }

  const token = authHeader.slice(7);
  console.log(`[${req.method} ${req.path}] JWT recibido: ${token.slice(0, 25)}...`);

  // 2) El token debe ser valido (firma, emisor, expiracion)
  try {
    const { payload } = await jwtVerify(token, JWKS, { issuer: ISSUER });
    req.usuario = payload.preferred_username || payload.sub;
    next();
  } catch (err) {
    console.log(`   Token invalido: ${err.message}`);
    return res.status(401).json({ error: "Token invalido o expirado" });
  }
}

// ---------- Rutas ----------
app.get("/health", (_req, res) => res.json({ status: "ok" }));

// Obtener el listado del usuario
app.get("/items", verificarToken, (req, res) => {
  res.json(itemsPorUsuario.get(req.usuario) || []);
});

// Agregar un elemento
app.post("/items", verificarToken, (req, res) => {
  const { nombre, marca, categoria, descripcion } = req.body || {};

  if (!nombre || !nombre.trim()) {
    return res.status(400).json({ error: "El nombre es obligatorio" });
  }

  const nuevo = {
    id: Date.now(),
    nombre: nombre.trim(),
    marca: (marca || "").trim(),
    categoria: (categoria || "").trim(),
    descripcion: (descripcion || "").trim(),
  };

  const lista = itemsPorUsuario.get(req.usuario) || [];
  lista.push(nuevo);
  itemsPorUsuario.set(req.usuario, lista);

  res.status(201).json(nuevo);
});

app.listen(PORT, () => {
  console.log(`Backend en http://localhost:${PORT}`);
  console.log(`Validando tokens de: ${ISSUER}`);
});
