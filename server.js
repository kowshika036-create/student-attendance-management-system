const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'super_secret_attendance_key_123';

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname)));

// Database Setup
const db = new sqlite3.Database('./database.db', (err) => {
  if (err) console.error('Database connection error:', err.message);
  else console.log('Connected to SQLite database.');
});

db.serialize(() => {
  db.run(`PRAGMA foreign_keys = ON;`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'teacher'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    roll_number TEXT UNIQUE NOT NULL,
    department TEXT NOT NULL,
    class_name TEXT NOT NULL,
    email TEXT,
    phone TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS subjects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_name TEXT NOT NULL,
    subject_code TEXT UNIQUE NOT NULL,
    department TEXT NOT NULL,
    semester INTEGER NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    subject_id INTEGER NOT NULL,
    attendance_date TEXT NOT NULL,
    status TEXT NOT NULL,
    FOREIGN KEY (student_id) REFERENCES students (id) ON DELETE CASCADE,
    FOREIGN KEY (subject_id) REFERENCES subjects (id) ON DELETE CASCADE,
    UNIQUE(student_id, subject_id, attendance_date)
  )`);

  // Default Admin Seeding
  db.get(`SELECT * FROM users WHERE username = ?`, ['admin'], (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync('admin123', 10);
      db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, ['admin', hash, 'admin']);
    }
  });
});

// Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied. Token missing.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
};

// Auth Route
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Invalid credentials.' });

    const validPassword = bcrypt.compareSync(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid credentials.' });

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, username: user.username, role: user.role });
  });
});

// Dashboard Route
app.get('/api/dashboard', authenticateToken, (req, res) => {
  const today = new Date().toISOString().split('T')[0];

  db.get(`SELECT COUNT(*) as totalStudents FROM students`, [], (err, totalRow) => {
    db.get(`SELECT COUNT(DISTINCT student_id) as presentToday FROM attendance WHERE attendance_date = ? AND status = 'Present'`, [today], (err, presentRow) => {
      db.get(`SELECT COUNT(DISTINCT student_id) as absentToday FROM attendance WHERE attendance_date = ? AND status = 'Absent'`, [today], (err, absentRow) => {
        db.all(`SELECT a.attendance_date, s.name as student_name, s.roll_number, sub.subject_name, a.status 
                FROM attendance a 
                JOIN students s ON a.student_id = s.id 
                JOIN subjects sub ON a.subject_id = sub.id 
                ORDER BY a.id DESC LIMIT 5`, [], (err, recent) => {
          
          const totalMarked = (presentRow.presentToday || 0) + (absentRow.absentToday || 0);
          const percentage = totalMarked > 0 ? Math.round((presentRow.presentToday / totalMarked) * 100) : 0;

          res.json({
            totalStudents: totalRow.totalStudents || 0,
            presentToday: presentRow.presentToday || 0,
            absentToday: absentRow.absentToday || 0,
            attendancePct: percentage,
            recentRecords: recent || []
          });
        });
      });
    });
  });
});

// Student Management Routes
app.get('/api/students', authenticateToken, (req, res) => {
  const search = req.query.search ? `%${req.query.search}%` : '%';
  db.all(`SELECT * FROM students WHERE name LIKE ? OR roll_number LIKE ? OR department LIKE ? OR class_name LIKE ? ORDER BY id DESC`, 
    [search, search, search, search], (err, rows) => {
      res.json(rows || []);
  });
});

app.post('/api/students', authenticateToken, (req, res) => {
  const { name, roll_number, department, class_name, email, phone } = req.body;
  db.run(`INSERT INTO students (name, roll_number, department, class_name, email, phone) VALUES (?, ?, ?, ?, ?, ?)`,
    [name, roll_number, department, class_name, email, phone], function(err) {
      if (err) return res.status(400).json({ error: 'Roll Number already exists.' });
      res.json({ id: this.lastID });
  });
});

app.delete('/api/students/:id', authenticateToken, (req, res) => {
  db.run(`DELETE FROM students WHERE id = ?`, [req.params.id], function(err) {
    res.json({ deleted: this.changes });
  });
});

// Subject Management Routes
app.get('/api/subjects', authenticateToken, (req, res) => {
  db.all(`SELECT * FROM subjects ORDER BY id DESC`, [], (err, rows) => {
    res.json(rows || []);
  });
});

app.post('/api/subjects', authenticateToken, (req, res) => {
  const { subject_name, subject_code, department, semester } = req.body;
  db.run(`INSERT INTO subjects (subject_name, subject_code, department, semester) VALUES (?, ?, ?, ?)`,
    [subject_name, subject_code, department, semester], function(err) {
      if (err) return res.status(400).json({ error: 'Subject Code already exists.' });
      res.json({ id: this.lastID });
  });
});

app.delete('/api/subjects/:id', authenticateToken, (req, res) => {
  db.run(`DELETE FROM subjects WHERE id = ?`, [req.params.id], function(err) {
    res.json({ deleted: this.changes });
  });
});

// Attendance Management Routes
app.get('/api/attendance/classes', authenticateToken, (req, res) => {
  db.all(`SELECT DISTINCT class_name FROM students ORDER BY class_name`, [], (err, rows) => {
    res.json(rows.map(r => r.class_name));
  });
});

app.get('/api/attendance/students', authenticateToken, (req, res) => {
  const { class_name } = req.query;
  db.all(`SELECT * FROM students WHERE class_name = ? ORDER BY roll_number`, [class_name], (err, rows) => {
    res.json(rows || []);
  });
});

app.post('/api/attendance', authenticateToken, (req, res) => {
  const { attendance_date, subject_id, records } = req.body; // records = [{ student_id, status }]
  
  let inserted = 0;
  let duplicates = 0;
  let completed = 0;

  if (!records || records.length === 0) return res.status(400).json({ error: 'No student records provided.' });

  records.forEach(record => {
    db.run(`INSERT INTO attendance (student_id, subject_id, attendance_date, status) VALUES (?, ?, ?, ?)`,
      [record.student_id, subject_id, attendance_date, record.status], function(err) {
        if (err) duplicates++;
        else inserted++;
        
        completed++;
        if (completed === records.length) {
          res.json({ message: `Attendance saved: ${inserted} added, ${duplicates} duplicates skipped.` });
        }
    });
  });
});

// Reports Route
app.get('/api/reports', authenticateToken, (req, res) => {
  const sql = `
    SELECT 
      s.id, s.name, s.roll_number, s.class_name, s.department,
      COUNT(a.id) as total_classes,
      SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END) as present_count,
      SUM(CASE WHEN a.status = 'Absent' THEN 1 ELSE 0 END) as absent_count
    FROM students s
    LEFT JOIN attendance a ON s.id = a.student_id
    GROUP BY s.id
    ORDER BY s.roll_number ASC
  `;

  db.all(sql, [], (err, rows) => {
    const reports = (rows || []).map(row => {
      const total = row.total_classes || 0;
      const present = row.present_count || 0;
      const absent = row.absent_count || 0;
      const pct = total > 0 ? Math.round((present / total) * 100) : 0;
      return {
        ...row,
        present_count: present,
        absent_count: absent,
        percentage: pct,
        isLow: pct < 75 && total > 0
      };
    });
    res.json(reports);
  });
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));