const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = 3000;

app.use(express.json());
app.use(cors());

// Database setup
const db = new sqlite3.Database('./notekeeper.db', (err) => {
    if (err) {
        console.error('Error opening database', err);
    } else {
        console.log('Connected to the SQLite database.');
        db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )`);
        db.run(`CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      title TEXT,
      content TEXT,
      color TEXT,
      is_archived BOOLEAN,
      is_trashed BOOLEAN,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`);
    }
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, 'your_jwt_secret', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Routes
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function (err) {
            if (err) {
                return res.status(400).json({ error: 'Username already exists' });
            }
            res.status(201).json({ message: 'User registered successfully' });
        });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Server error' });
        if (!user) return res.status(400).json({ error: 'User not found' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid password' });

        const token = jwt.sign({ id: user.id, username: user.username }, 'your_jwt_secret');
        res.json({ token });
    });
});

app.get('/notes', authenticateToken, (req, res) => {
    db.all('SELECT * FROM notes WHERE user_id = ?', [req.user.id], (err, notes) => {
        if (err) return res.status(500).json({ error: 'Error fetching notes' });
        res.json(notes);
    });
});

app.post('/notes', authenticateToken, (req, res) => {
    const { title, content, color } = req.body;
    db.run('INSERT INTO notes (user_id, title, content, color, is_archived, is_trashed) VALUES (?, ?, ?, ?, 0, 0)',
        [req.user.id, title, content, color],
        function (err) {
            if (err) return res.staatus(500).json({ error: 'Error creating note' });
            res.status(201).json({ id: this.lastID });
        }
    );
});

app.put('/notes/:id', authenticateToken, (req, res) => {
    const { title, content, color, is_archived, is_trashed } = req.body;
    db.run('UPDATE notes SET title = ?, content = ?, color = ?, is_archived = ?, is_trashed = ? WHERE id = ? AND user_id = ?',
        [title, content, color, is_archived, is_trashed, req.params.id, req.user.id],
        function (err) {
            if (err) return res.status(500).json({ error: 'Error updating note' });
            if (this.changes === 0) return res.status(404).json({ error: 'Note not found' });
            res.json({ message: 'Note updated successfully' });
        }
    );
});

app.delete('/notes/:id', authenticateToken, (req, res) => {
    db.run('DELETE FROM notes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], function (err) {
        if (err) return res.status(500).json({ error: 'Error deleting note' });
        if (this.changes === 0) return res.status(404).json({ error: 'Note not found' });
        res.json({ message: 'Note deleted successfully' });
    });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
