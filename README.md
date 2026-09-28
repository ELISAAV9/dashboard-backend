# Dashboard Backend

API en Express que protege el listado de favoritos con el JWT emitido por Keycloak.

## Requisitos
- Node.js 18+
- Keycloak corriendo en http://localhost:8081 (realm `cybersecurity`)

## Uso
```bash
npm install
cp .env.example .env
npm start
```

## Endpoints (requieren `Authorization: Bearer <JWT>`)
| Metodo | Ruta     | Descripcion                  |
|--------|----------|------------------------------|
| GET    | /items   | Lista los elementos          |
| POST   | /items   | Agrega un elemento           |
| GET    | /health  | Estado (sin token)           |

Body de POST: `{ "nombre": "...", "categoria": "...", "descripcion": "..." }`
