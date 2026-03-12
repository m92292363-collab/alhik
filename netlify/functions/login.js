const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { sql, initDB } = require('./_db');

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };

  try {
    await initDB();
    const { identifier, password, role } = JSON.parse(event.body);

    if (!identifier || !password) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Missing credentials' }) };
    }

    let user = null;
    let userRole = null;
    let faculty = null;

    if (role === 'student') {
      // Student login
      const rows = await sql`SELECT * FROM students WHERE student_id = ${identifier}`;
      if (rows.length > 0) {
        user = rows[0];
        userRole = 'student';
        faculty = user.faculty;
      }
    } else {
      // Admin or staff login (management portal)
      const adminRows = await sql`SELECT * FROM admins WHERE username = ${identifier}`;
      if (adminRows.length > 0) {
        user = adminRows[0];
        userRole = 'admin';
      } else {
        const staffRows = await sql`SELECT * FROM staff WHERE username = ${identifier}`;
        if (staffRows.length > 0) {
          user = staffRows[0];
          userRole = 'staff';
          faculty = user.faculty;
        }
      }
    }

    if (!user) {
      return { statusCode: 401, body: JSON.stringify({ error: 'Invalid credentials' }) };
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return { statusCode: 401, body: JSON.stringify({ error: 'Invalid credentials' }) };
    }

    const payload = {
      id: user.id,
      role: userRole,
      name: user.name,
      ...(userRole === 'student' && { student_id: user.student_id }),
      ...(faculty && { faculty })
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

    return {
      statusCode: 200,
      body: JSON.stringify({
        token,
        role: userRole,
        name: user.name,
        faculty: faculty || null
      })
    };
  } catch (err) {
    console.error(err);
    return { statusCode: 500, body: JSON.stringify({ error: 'Server error' }) };
  }
};
