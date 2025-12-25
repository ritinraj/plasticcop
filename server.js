/**
 * EcoReport Backend Server
 * Complete Node.js/Express backend with:
 * - Email OTP Authentication
 * - SQLite Database
 * - Image Upload to Cloud Storage
 * - RESTful API endpoints
 */

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// ==================== CONFIGURATION ====================
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const OTP_EXPIRY_MINUTES = 5;
const MAX_OTP_ATTEMPTS = 3;

// Email Configuration (Update with your SMTP settings)
const EMAIL_CONFIG = {
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: process.env.SMTP_PORT || 587,
    secure: false,
    auth: {
        user: process.env.SMTP_USER || 'your-email@gmail.com',
        pass: process.env.SMTP_PASS || 'your-app-password'
    }
};

// ==================== DATABASE SETUP (SQLite) ====================
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./ecoreport.db');

// Initialize database tables
db.serialize(() => {
    // Users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT,
            phone TEXT,
            role TEXT DEFAULT 'citizen',
            city TEXT,
            points INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // OTP table
    db.run(`
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            otp_code TEXT NOT NULL,
            expiry_time DATETIME NOT NULL,
            verified INTEGER DEFAULT 0,
            attempts INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Reports table
    db.run(`
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            image_url TEXT NOT NULL,
            plastic_type TEXT NOT NULL,
            quantity TEXT NOT NULL,
            city TEXT NOT NULL,
            description TEXT NOT NULL,
            notes TEXT,
            status TEXT DEFAULT 'submitted',
            verified_by INTEGER,
            admin_remarks TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (verified_by) REFERENCES users(id)
        )
    `);

    // Sessions table
    db.run(`
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    console.log('Database initialized successfully');
});

// ==================== EXPRESS APP SETUP ====================
const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

// Multer configuration for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, './uploads');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'report-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (extname && mimetype) {
            return cb(null, true);
        }
        cb(new Error('Only image files are allowed'));
    }
});

// ==================== EMAIL SERVICE ====================
const transporter = nodemailer.createTransport(EMAIL_CONFIG);

async function sendOTPEmail(email, otp) {
    const mailOptions = {
        from: `"EcoReport" <${EMAIL_CONFIG.auth.user}>`,
        to: email,
        subject: 'Your EcoReport Verification Code',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #22c55e, #16a34a); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0;">🌿 EcoReport</h1>
                    <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0 0;">Plastic Waste Reporting Platform</p>
                </div>
                <div style="padding: 30px; background: #f9fafb;">
                    <h2 style="color: #1f2937; margin-top: 0;">Verification Code</h2>
                    <p style="color: #4b5563;">Your one-time verification code is:</p>
                    <div style="background: white; border: 2px solid #22c55e; border-radius: 10px; padding: 20px; text-align: center; margin: 20px 0;">
                        <span style="font-size: 32px; font-weight: bold; color: #22c55e; letter-spacing: 8px;">${otp}</span>
                    </div>
                    <p style="color: #6b7280; font-size: 14px;">This code is valid for ${OTP_EXPIRY_MINUTES} minutes.</p>
                    <p style="color: #6b7280; font-size: 14px;">If you didn't request this code, please ignore this email.</p>
                </div>
                <div style="padding: 20px; background: #1f2937; text-align: center;">
                    <p style="color: #9ca3af; margin: 0; font-size: 12px;">© 2024 EcoReport. All rights reserved.</p>
                </div>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('Email send error:', error);
        return false;
    }
}

// ==================== HELPER FUNCTIONS ====================
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateToken(userId) {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

// Authentication middleware
function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);
    
    if (!decoded) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }

    db.get('SELECT * FROM users WHERE id = ?', [decoded.userId], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'User not found' });
        }
        req.user = user;
        next();
    });
}

// Admin middleware
function requireAdmin(req, res, next) {
    if (req.user.role !== 'municipality' && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

// Promisify database operations
function dbRun(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) reject(err);
            else resolve({ lastID: this.lastID, changes: this.changes });
        });
    });
}

function dbGet(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function dbAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

// ==================== API ROUTES ====================

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'EcoReport API is running' });
});

// -------------------- AUTH ROUTES --------------------

// Request OTP
app.post('/api/auth/request-otp', async (req, res) => {
    try {
        const { email, name, phone, role, city } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        // Check for rate limiting (max 3 attempts per 5 minutes)
        const recentAttempts = await dbGet(
            `SELECT COUNT(*) as count FROM otps 
             WHERE email = ? AND created_at > datetime('now', '-5 minutes')`,
            [email]
        );

        if (recentAttempts && recentAttempts.count >= MAX_OTP_ATTEMPTS) {
            return res.status(429).json({ 
                error: 'Too many OTP requests. Please try again later.' 
            });
        }

        // Generate OTP
        const otp = generateOTP();
        const expiryTime = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

        // Store OTP
        await dbRun(
            `INSERT INTO otps (email, otp_code, expiry_time) VALUES (?, ?, ?)`,
            [email, otp, expiryTime.toISOString()]
        );

        // Check if user exists, if not create
        let user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
        
        if (!user) {
            await dbRun(
                `INSERT INTO users (email, name, phone, role, city) VALUES (?, ?, ?, ?, ?)`,
                [email, name || '', phone || '', role || 'citizen', city || '']
            );
        } else if (name || phone || city) {
            // Update user info if provided
            await dbRun(
                `UPDATE users SET 
                 name = COALESCE(?, name),
                 phone = COALESCE(?, phone),
                 city = COALESCE(?, city)
                 WHERE email = ?`,
                [name, phone, city, email]
            );
        }

        // Send OTP email
        const emailSent = await sendOTPEmail(email, otp);

        if (!emailSent) {
            // For development, return OTP if email fails
            console.log(`OTP for ${email}: ${otp}`);
            return res.json({ 
                success: true, 
                message: 'OTP generated (check server logs in dev mode)',
                devOtp: process.env.NODE_ENV !== 'production' ? otp : undefined
            });
        }

        res.json({ success: true, message: 'OTP sent to your email' });

    } catch (error) {
        console.error('Request OTP error:', error);
        res.status(500).json({ error: 'Failed to send OTP' });
    }
});

// Verify OTP
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ error: 'Email and OTP are required' });
        }

        // Find valid OTP
        const otpRecord = await dbGet(
            `SELECT * FROM otps 
             WHERE email = ? AND otp_code = ? AND verified = 0 
             AND expiry_time > datetime('now')
             ORDER BY created_at DESC LIMIT 1`,
            [email, otp]
        );

        if (!otpRecord) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        // Mark OTP as verified
        await dbRun('UPDATE otps SET verified = 1 WHERE id = ?', [otpRecord.id]);

        // Get user
        const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);

        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        // Generate session token
        const token = generateToken(user.id);

        // Store session
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
        await dbRun(
            'INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)',
            [user.id, token, expiresAt.toISOString()]
        );

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                phone: user.phone,
                role: user.role,
                city: user.city,
                points: user.points
            }
        });

    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({ error: 'Failed to verify OTP' });
    }
});

// Get current user
app.get('/api/auth/me', authenticate, (req, res) => {
    res.json({
        user: {
            id: req.user.id,
            email: req.user.email,
            name: req.user.name,
            phone: req.user.phone,
            role: req.user.role,
            city: req.user.city,
            points: req.user.points
        }
    });
});

// Update user profile
app.put('/api/auth/profile', authenticate, async (req, res) => {
    try {
        const { name, phone, city } = req.body;

        await dbRun(
            `UPDATE users SET name = ?, phone = ?, city = ? WHERE id = ?`,
            [name || req.user.name, phone || req.user.phone, city || req.user.city, req.user.id]
        );

        const updatedUser = await dbGet('SELECT * FROM users WHERE id = ?', [req.user.id]);

        res.json({
            success: true,
            user: {
                id: updatedUser.id,
                email: updatedUser.email,
                name: updatedUser.name,
                phone: updatedUser.phone,
                role: updatedUser.role,
                city: updatedUser.city,
                points: updatedUser.points
            }
        });

    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Logout
app.post('/api/auth/logout', authenticate, async (req, res) => {
    try {
        const token = req.headers.authorization.split(' ')[1];
        await dbRun('DELETE FROM sessions WHERE token = ?', [token]);
        res.json({ success: true, message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Failed to logout' });
    }
});

// -------------------- REPORTS ROUTES --------------------

// Create report with image upload
app.post('/api/reports', authenticate, upload.single('image'), async (req, res) => {
    try {
        const { plasticType, quantity, city, description, notes } = req.body;

        if (!req.file && !req.body.imageBase64) {
            return res.status(400).json({ error: 'Image is required' });
        }

        let imageUrl;

        if (req.file) {
            // File uploaded via multipart form
            imageUrl = `/uploads/${req.file.filename}`;
        } else if (req.body.imageBase64) {
            // Base64 image
            const base64Data = req.body.imageBase64.replace(/^data:image\/\w+;base64,/, '');
            const buffer = Buffer.from(base64Data, 'base64');
            const filename = `report-${Date.now()}-${Math.round(Math.random() * 1E9)}.jpg`;
            const filepath = `./uploads/${filename}`;
            fs.writeFileSync(filepath, buffer);
            imageUrl = `/uploads/${filename}`;
        }

        const result = await dbRun(
            `INSERT INTO reports (user_id, image_url, plastic_type, quantity, city, description, notes)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [req.user.id, imageUrl, plasticType, quantity, city, description, notes || '']
        );

        // Award points for submitting report
        await dbRun(
            'UPDATE users SET points = points + 10 WHERE id = ?',
            [req.user.id]
        );

        const report = await dbGet('SELECT * FROM reports WHERE id = ?', [result.lastID]);

        res.json({
            success: true,
            message: 'Report submitted successfully! +10 points',
            report
        });

    } catch (error) {
        console.error('Create report error:', error);
        res.status(500).json({ error: 'Failed to create report' });
    }
});

// Get user's reports
app.get('/api/reports/my', authenticate, async (req, res) => {
    try {
        const reports = await dbAll(
            `SELECT r.*, u.name as user_name, u.email as user_email
             FROM reports r
             JOIN users u ON r.user_id = u.id
             WHERE r.user_id = ?
             ORDER BY r.created_at DESC`,
            [req.user.id]
        );

        res.json({ reports });

    } catch (error) {
        console.error('Get my reports error:', error);
        res.status(500).json({ error: 'Failed to fetch reports' });
    }
});

// Get single report
app.get('/api/reports/:id', authenticate, async (req, res) => {
    try {
        const report = await dbGet(
            `SELECT r.*, u.name as user_name, u.email as user_email,
                    v.name as verified_by_name
             FROM reports r
             JOIN users u ON r.user_id = u.id
             LEFT JOIN users v ON r.verified_by = v.id
             WHERE r.id = ?`,
            [req.params.id]
        );

        if (!report) {
            return res.status(404).json({ error: 'Report not found' });
        }

        // Check access (own report or admin)
        if (report.user_id !== req.user.id && 
            req.user.role !== 'municipality' && 
            req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        res.json({ report });

    } catch (error) {
        console.error('Get report error:', error);
        res.status(500).json({ error: 'Failed to fetch report' });
    }
});

// Get user stats
app.get('/api/reports/stats/user', authenticate, async (req, res) => {
    try {
        const stats = await dbGet(
            `SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'submitted' THEN 1 ELSE 0 END) as submitted,
                SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END) as verified,
                SUM(CASE WHEN status = 'collected' THEN 1 ELSE 0 END) as collected,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
             FROM reports WHERE user_id = ?`,
            [req.user.id]
        );

        const user = await dbGet('SELECT points FROM users WHERE id = ?', [req.user.id]);

        res.json({
            total: stats.total || 0,
            submitted: stats.submitted || 0,
            verified: stats.verified || 0,
            collected: stats.collected || 0,
            rejected: stats.rejected || 0,
            points: user.points || 0
        });

    } catch (error) {
        console.error('Get user stats error:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// -------------------- ADMIN ROUTES --------------------

// Get all reports (admin)
app.get('/api/admin/reports', authenticate, requireAdmin, async (req, res) => {
    try {
        const { city, status, dateFrom, dateTo } = req.query;
        
        let sql = `
            SELECT r.*, u.name as user_name, u.email as user_email,
                   v.name as verified_by_name
            FROM reports r
            JOIN users u ON r.user_id = u.id
            LEFT JOIN users v ON r.verified_by = v.id
            WHERE 1=1
        `;
        const params = [];

        // Filter by municipality's city if not super admin
        if (req.user.role === 'municipality' && req.user.city) {
            sql += ' AND r.city = ?';
            params.push(req.user.city);
        }

        if (city) {
            sql += ' AND r.city = ?';
            params.push(city);
        }

        if (status) {
            sql += ' AND r.status = ?';
            params.push(status);
        }

        if (dateFrom) {
            sql += ' AND r.created_at >= ?';
            params.push(dateFrom);
        }

        if (dateTo) {
            sql += ' AND r.created_at <= ?';
            params.push(dateTo + 'T23:59:59');
        }

        sql += ' ORDER BY r.created_at DESC';

        const reports = await dbAll(sql, params);

        res.json({ reports });

    } catch (error) {
        console.error('Get admin reports error:', error);
        res.status(500).json({ error: 'Failed to fetch reports' });
    }
});

// Get admin stats
app.get('/api/admin/stats', authenticate, requireAdmin, async (req, res) => {
    try {
        let sql = `
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'submitted' THEN 1 ELSE 0 END) as submitted,
                SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END) as verified,
                SUM(CASE WHEN status = 'collected' THEN 1 ELSE 0 END) as collected,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
            FROM reports
        `;
        const params = [];

        // Filter by municipality's city if not super admin
        if (req.user.role === 'municipality' && req.user.city) {
            sql += ' WHERE city = ?';
            params.push(req.user.city);
        }

        const stats = await dbGet(sql, params);

        // Get unique cities
        const cities = await dbAll('SELECT DISTINCT city FROM reports ORDER BY city');

        res.json({
            total: stats.total || 0,
            submitted: stats.submitted || 0,
            verified: stats.verified || 0,
            collected: stats.collected || 0,
            rejected: stats.rejected || 0,
            cities: cities.map(c => c.city)
        });

    } catch (error) {
        console.error('Get admin stats error:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// Update report status (admin)
app.put('/api/admin/reports/:id/status', authenticate, requireAdmin, async (req, res) => {
    try {
        const { status, remarks } = req.body;
        const reportId = req.params.id;

        if (!['submitted', 'verified', 'collected', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        const report = await dbGet('SELECT * FROM reports WHERE id = ?', [reportId]);

        if (!report) {
            return res.status(404).json({ error: 'Report not found' });
        }

        // Check city access for municipality
        if (req.user.role === 'municipality' && req.user.city && report.city !== req.user.city) {
            return res.status(403).json({ error: 'Access denied to this report' });
        }

        const oldStatus = report.status;

        await dbRun(
            `UPDATE reports 
             SET status = ?, verified_by = ?, admin_remarks = ?, updated_at = datetime('now')
             WHERE id = ?`,
            [status, req.user.id, remarks || report.admin_remarks, reportId]
        );

        // Award points based on status change
        let pointsAwarded = 0;
        if (status === 'verified' && oldStatus === 'submitted') {
            pointsAwarded = 5;
        } else if (status === 'collected' && oldStatus !== 'collected') {
            pointsAwarded = 15;
        }

        if (pointsAwarded > 0) {
            await dbRun(
                'UPDATE users SET points = points + ? WHERE id = ?',
                [pointsAwarded, report.user_id]
            );
        }

        const updatedReport = await dbGet(
            `SELECT r.*, u.name as user_name, u.email as user_email
             FROM reports r
             JOIN users u ON r.user_id = u.id
             WHERE r.id = ?`,
            [reportId]
        );

        res.json({
            success: true,
            message: `Report status updated to ${status}`,
            report: updatedReport,
            pointsAwarded
        });

    } catch (error) {
        console.error('Update report status error:', error);
        res.status(500).json({ error: 'Failed to update report status' });
    }
});

// Export reports to CSV
app.get('/api/admin/export', authenticate, requireAdmin, async (req, res) => {
    try {
        const { city, status, dateFrom, dateTo } = req.query;
        
        let sql = `
            SELECT r.id, u.name as user_name, u.email as user_email,
                   r.plastic_type, r.quantity, r.city, r.description,
                   r.notes, r.status, r.created_at, r.admin_remarks
            FROM reports r
            JOIN users u ON r.user_id = u.id
            WHERE 1=1
        `;
        const params = [];

        if (req.user.role === 'municipality' && req.user.city) {
            sql += ' AND r.city = ?';
            params.push(req.user.city);
        }

        if (city) {
            sql += ' AND r.city = ?';
            params.push(city);
        }

        if (status) {
            sql += ' AND r.status = ?';
            params.push(status);
        }

        if (dateFrom) {
            sql += ' AND r.created_at >= ?';
            params.push(dateFrom);
        }

        if (dateTo) {
            sql += ' AND r.created_at <= ?';
            params.push(dateTo + 'T23:59:59');
        }

        sql += ' ORDER BY r.created_at DESC';

        const reports = await dbAll(sql, params);

        // Generate CSV
        const headers = ['Report ID', 'User Name', 'User Email', 'Plastic Type', 'Quantity', 'City', 'Description', 'Notes', 'Status', 'Created At', 'Admin Remarks'];
        const rows = reports.map(r => [
            r.id,
            `"${(r.user_name || '').replace(/"/g, '""')}"`,
            r.user_email,
            r.plastic_type,
            r.quantity,
            r.city,
            `"${(r.description || '').replace(/"/g, '""')}"`,
            `"${(r.notes || '').replace(/"/g, '""')}"`,
            r.status,
            r.created_at,
            `"${(r.admin_remarks || '').replace(/"/g, '""')}"`
        ]);

        const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename=ecoreport-export-${new Date().toISOString().split('T')[0]}.csv`);
        res.send(csv);

    } catch (error) {
        console.error('Export error:', error);
        res.status(500).json({ error: 'Failed to export reports' });
    }
});

// Get all users (admin)
app.get('/api/admin/users', authenticate, requireAdmin, async (req, res) => {
    try {
        const users = await dbAll(
            `SELECT id, email, name, phone, role, city, points, created_at
             FROM users ORDER BY created_at DESC`
        );

        res.json({ users });

    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Update user role (super admin only)
app.put('/api/admin/users/:id/role', authenticate, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Super admin access required' });
        }

        const { role, city } = req.body;
        const userId = req.params.id;

        if (!['citizen', 'municipality', 'admin'].includes(role)) {
            return res.status(400).json({ error: 'Invalid role' });
        }

        await dbRun(
            'UPDATE users SET role = ?, city = ? WHERE id = ?',
            [role, city || null, userId]
        );

        const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);

        res.json({
            success: true,
            message: 'User role updated',
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                city: user.city
            }
        });

    } catch (error) {
        console.error('Update user role error:', error);
        res.status(500).json({ error: 'Failed to update user role' });
    }
});

// ==================== SERVE FRONTEND ====================
app.use(express.static('.'));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ==================== START SERVER ====================
app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🌿 EcoReport Backend Server                             ║
║                                                           ║
║   Server running on: http://localhost:${PORT}               ║
║   API Base URL:      http://localhost:${PORT}/api           ║
║                                                           ║
║   Endpoints:                                              ║
║   POST /api/auth/request-otp  - Request OTP              ║
║   POST /api/auth/verify-otp   - Verify OTP               ║
║   GET  /api/auth/me           - Get current user         ║
║   POST /api/reports           - Create report            ║
║   GET  /api/reports/my        - Get user's reports       ║
║   GET  /api/admin/reports     - Get all reports (admin)  ║
║   PUT  /api/admin/reports/:id - Update status (admin)    ║
║   GET  /api/admin/export      - Export CSV (admin)       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    `);
});

// ==================== GRACEFUL SHUTDOWN ====================
process.on('SIGINT', () => {
    console.log('\nShutting down server...');
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err);
        } else {
            console.log('Database connection closed.');
        }
        process.exit(0);
    });
});

module.exports = app;