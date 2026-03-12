// netlify/functions/login.js
// Handles login for: students (via login.html) + staff/admin (via management.html)

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { sql, initDB, CORS_HEADERS } = require('./_db');

const JWT_SECRET = process.env.JWT_SECRET;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

exports.handler = async (event) => {
    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers: CORS_HEADERS, body: '' };
    }
    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, headers: CORS_HEADERS, body: JSON.stringify({ message: 'Method not allowed' }) };
    }

    try {
        await initDB();

        const { loginId, password, portal } = JSON.parse(event.body);
        // portal: 'student' = came from login.html | 'management' = came from management.html

        if (!loginId || !password) {
            return {
                statusCode: 400,
                headers: CORS_HEADERS,
                body: JSON.stringify({ message: 'Login ID and password are required.' })
            };
        }

        const identifier = loginId.trim().toLowerCase();

        // ── Brute-force check ──
        const [attempt] = await sql`
            SELECT * FROM login_attempts WHERE identifier = ${identifier}
        `;

        if (attempt?.locked_until && new Date(attempt.locked_until) > new Date()) {
            const minutesLeft = Math.ceil((new Date(attempt.locked_until) - new Date()) / 60000);
            return {
                statusCode: 429,
                headers: CORS_HEADERS,
                body: JSON.stringify({ message: `Account locked. Try again in ${minutesLeft} minute(s).` })
            };
        }

        // ── Route by portal ──
        if (portal === 'student') {
            // Look in students table only
            const [user] = await sql`
                SELECT * FROM students WHERE LOWER(student_id) = ${identifier} AND role = 'student'
            `;

            if (!user) {
                await recordFailedAttempt(identifier, attempt);
                return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ message: 'Invalid credentials.' }) };
            }

            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                await recordFailedAttempt(identifier, attempt);
                return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ message: 'Invalid credentials.' }) };
            }

            await sql`DELETE FROM login_attempts WHERE identifier = ${identifier}`;

            const token = jwt.sign(
                { id: user.id, studentId: user.student_id, role: 'student', faculty: user.faculty },
                JWT_SECRET,
                { expiresIn: '8h' }
            );

            return {
                statusCode: 200,
                headers: CORS_HEADERS,
                body: JSON.stringify({
                    token,
                    user: {
                        studentId: user.student_id,
                        name: user.name,
                        email: user.email,
                        faculty: user.faculty,
                        department: user.department,
                        year: user.year,
                        role: 'student',
                    }
                })
            };
        }

        if (portal === 'management') {
            // Look in staff table (includes both 'staff' and 'admin' roles)
            const [user] = await sql`
                SELECT * FROM staff WHERE LOWER(staff_id) = ${identifier}
            `;

            if (!user) {
                await recordFailedAttempt(identifier, attempt);
                return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ message: 'Invalid credentials.' }) };
            }

            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                await recordFailedAttempt(identifier, attempt);
                return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ message: 'Invalid credentials.' }) };
            }

            await sql`DELETE FROM login_attempts WHERE identifier = ${identifier}`;

            // JWT includes faculty scope — null for admin (all access), set for staff (limited)
            const token = jwt.sign(
                {
                    id: user.id,
                    staffId: user.staff_id,
                    role: user.role,                    // 'admin' or 'staff'
                    faculty: user.faculty || null,      // null = admin (all faculties)
                },
                JWT_SECRET,
                { expiresIn: '8h' }
            );

            return {
                statusCode: 200,
                headers: CORS_HEADERS,
                body: JSON.stringify({
                    token,
                    user: {
                        staffId: user.staff_id,
                        name: user.name,
                        email: user.email,
                        faculty: user.faculty,
                        role: user.role,
                    }
                })
            };
        }

        return {
            statusCode: 400,
            headers: CORS_HEADERS,
            body: JSON.stringify({ message: 'Invalid portal specified.' })
        };

    } catch (err) {
        console.error('Login error:', err);
        return {
            statusCode: 500,
            headers: CORS_HEADERS,
            body: JSON.stringify({ message: 'Server error. Please try again.' })
        };
    }
};

async function recordFailedAttempt(identifier, existing) {
    const newCount = (existing?.attempts || 0) + 1;
    const lockedUntil = newCount >= MAX_ATTEMPTS
        ? new Date(Date.now() + LOCKOUT_MINUTES * 60000)
        : null;

    if (existing) {
        await sql`
            UPDATE login_attempts
            SET attempts = ${newCount}, locked_until = ${lockedUntil}, updated_at = NOW()
            WHERE identifier = ${identifier}
        `;
    } else {
        await sql`
            INSERT INTO login_attempts (identifier, attempts, locked_until)
            VALUES (${identifier}, ${newCount}, ${lockedUntil})
        `;
    }
}
