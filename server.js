import express from "express";
import cors from "cors";
import { createRemoteJWKSet, jwtVerify } from "jose";

const PORT = process.env.PORT || 3000;

// Dos URLs distintas a proposito:
// - JWKS_URL: donde el backend (dentro de Docker) va a buscar las llaves publicas.
//   Dentro de un contenedor, "localhost" es el propio contenedor, por eso aqui
//   usamos host.docker.internal para llegar a Keycloak, que corre en el host.
// - ISSUER_URL: el valor EXACTO que Keycloak escribe en el campo "iss" del JWT.
//   Como el login se pide desde fuera de Docker (http://localhost:8081), el
//   token siempre trae ese mismo valor como emisor, y debe coincidir tal cual.
const JWKS_URL = process.env.KEYCLOAK_JWKS_URL || "http://host.docker.internal:8081";
const ISSUER_URL = process.env.KEYCLOAK_ISSUER_URL || "http://localhost:8081";
const REALM = process.env.KEYCLOAK_REALM || "cybersecurity";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:8082";

const ISSUER = `${ISSUER_URL}/realms/${REALM}`;
const JWKS = createRemoteJWKSet(
  new URL(`${JWKS_URL}/realms/${REALM}/protocol/openid-connect/certs`)
);

const app = express();
app.use(cors({ origin: FRONTEND_ORIGIN }));
app.use(express.json());

const itemsPorUsuario = new Map();

async function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.log(`[${req.method} ${req.path}] SIN token -> 401`);
    return res.status(401).json({ error: "Falta el Bearer Token" });
  }

  const token = authHeader.slice(7);
  console.log(`[${req.method} ${req.path}] JWT recibido: ${token.slice(0, 25)}...`);

  try {
    const { payload } = await jwtVerify(token, JWKS, { issuer: ISSUER });
    req.usuario = payload.preferred_username || payload.sub;
    next();
  } catch (err) {
    console.log(`   Token invalido: ${err.message}`);
    return res.status(401).json({ error: "Token invalido o expirado" });
  }
}

app.get("/health", (_req, res) => res.json({ status: "ok" }));

app.get("/items", verificarToken, (req, res) => {
  res.json(itemsPorUsuario.get(req.usuario) || []);
});

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
  console.log(`Buscando llaves en:  ${JWKS_URL}/realms/${REALM}`);
  console.log(`Exigiendo issuer:    ${ISSUER}`);
});
