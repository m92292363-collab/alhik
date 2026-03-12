const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { sql, initDB } = require('./_db');

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';

function auth(event) {
  const token = (event.headers.authorization || '').replace('Bearer ', '');
  const decoded = jwt.verify(token, JWT_SECRET);
  if (decoded.role !== 'admin') throw new Error('Admin only');
  return decoded;
}

exports.handler = async (event) => {
  try {
    await initDB();
    auth(event);

    if (event.httpMethod === 'GET') {
      const staff = await sql`SELECT id, name, username, faculty FROM staff ORDER BY name`;
      return { statusCode: 200, body: JSON.stringify({ staff }) };
    }

    if (event.httpMethod === 'POST') {
      const { name, username, faculty, password } = JSON.parse(event.body);
      const hash = await bcrypt.hash(password, 10);
      await sql`INSERT INTO staff (name, username, faculty, password_hash) VALUES (${name}, ${username}, ${faculty}, ${hash})`;
      return { statusCode: 201, body: JSON.stringify({ success: true }) };
    }

    if (event.httpMethod === 'DELETE') {
      const { id } = JSON.parse(event.body);
      await sql`DELETE FROM staff WHERE id = ${id}`;
      return { statusCode: 200, body: JSON.stringify({ success: true }) };
    }

    return { statusCode: 405, body: 'Method Not Allowed' };
  } catch (err) {
    console.error(err);
    const status = err.message === 'Admin only' ? 403 : 500;
    return { statusCode: status, body: JSON.stringify({ error: err.message }) };
  }
};
