require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const swaggerJsDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const cors = require('cors');
const app = express();
app.use(express.json());



// Configuración de PostgreSQL
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});


app.use(cors({
  origin: '*', // URL de tu frontend Angular
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
// Middleware JWT
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Swagger setup
const swaggerOptions = {
  swaggerDefinition: {
    openapi: '3.0.0',
    info: { title: 'API Node PostgreSQL JWT', version: '1.0.0' },
    servers: [{ url: `http://localhost:${process.env.PORT || 3000}` }],
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }
      }
    }
  },
  apis: ['./index.js']
};
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerJsDoc(swaggerOptions)));

/* ================= LOGIN ================= */
/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login y obtiene token JWT
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             example:
 *               username: "admin@piar.com"
 *               password: "admin"
 *     responses:
 *       200:
 *         description: Devuelve token y usuario
 */
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const { rows } = await pool.query(
      `SELECT usuario_id, nombre, apellido, correo FROM usuarios WHERE correo=$1 AND contrasena=$2 AND activo=true`,
      [username, password]
    );
    const user = rows[0];
    if (!user) return res.status(400).json({ message: 'Correo o contraseña incorrectos' });

    const token = jwt.sign({ id: user.usuario_id, correo: user.correo }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, usuario: user });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ================= ENDPOINT DINÁMICO ================= */
/**
 * @swagger
 * /execute-sp:
 *   post:
 *     summary: Ejecuta cualquier SP o función dinámicamente
 *     tags: [SP]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             example:
 *               spName: "sp_registrar_usuario"
 *               params: ["Carlos","Gómez","carlos@correo.com","12345",2,null]
 *     responses:
 *       200:
 *         description: Resultado de SP o función
 */
app.post('/execute-sp', authenticateToken, async (req, res) => {
  const { spName, params } = req.body;
  try {
    if (!spName || !Array.isArray(params)) 
      return res.status(400).json({ message: 'spName y params son requeridos' });

    // Detecta si es PROCEDURE o FUNCTION
    const isProcedure = spName.startsWith('sp_');
    const isFunction = spName.startsWith('fn_') || spName.startsWith('consultar_');

    if (isProcedure) {
      // Llamada a PROCEDURE: incluir OUT como null
      const placeholders = params.map((_, i) => `$${i + 1}`).join(',');
      const query = `CALL ${spName}(${placeholders})`;
      await pool.query(query, params);
      return res.json({ message: `${spName} ejecutado correctamente` });

    } else if (isFunction) {
      const placeholders = params.map((_, i) => `$${i + 1}`).join(',');
      const query = `SELECT * FROM ${spName}(${placeholders})`;
      const { rows } = await pool.query(query, params);
      return res.json(rows);

    } else {
      return res.status(400).json({ message: 'No se reconoce si es FUNCTION o PROCEDURE' });
    }

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.listen(process.env.PORT || 3000, () => console.log(`Server running on port ${process.env.PORT || 3000}`));
