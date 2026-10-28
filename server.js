require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const initSqlJs = require('sql.js');
const fs = require('fs');
const sanitizeHtml = require('sanitize-html');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.json());
app.use(express.static('public'));

const DB_FILE = 'linechat.db';
let db;

const MESSAGE_LIMIT = 20;
const RATE_WINDOW = 60000;

async function initDB() {
    const SQL = await initSqlJs();
    if (fs.existsSync(DB_FILE)) db = new SQL.Database(fs.readFileSync(DB_FILE));
    else db = new SQL.Database();

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        passwordHash TEXT NOT NULL,
        lastSeen DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        text TEXT NOT NULL,
        time TEXT NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        owner TEXT NOT NULL,
        type TEXT DEFAULT 'group',
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS group_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        groupId INTEGER NOT NULL,
        username TEXT NOT NULL,
        role TEXT DEFAULT 'member'
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS group_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        groupId INTEGER NOT NULL,
        sender TEXT NOT NULL,
        text TEXT NOT NULL,
        time TEXT NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT NOT NULL,
        contactUsername TEXT NOT NULL,
        UNIQUE(owner, contactUsername)
    )`);

    saveDB();
    console.log('دیتابیس آماده شد.');
}

function saveDB() {
    fs.writeFileSync(DB_FILE, Buffer.from(db.export()));
}

function cleanText(text) {
    return sanitizeHtml(text, { allowedTags: [], allowedAttributes: {} }).trim();
}

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'همه فیلدها الزامی است.' });
    if (password.length < 4) return res.status(400).json({ error: 'رمز حداقل ۴ کاراکتر.' });

    const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
    stmt.bind([username]);
    if (stmt.step()) { stmt.free(); return res.status(400).json({ error: 'نام کاربری تکراری است.' }); }
    stmt.free();

    const hash = await bcrypt.hash(password, 12);
    db.run('INSERT INTO users (username, passwordHash) VALUES (?, ?)', [username, hash]);
    saveDB();
    res.json({ success: true });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
    stmt.bind([username]);
    if (!stmt.step()) { stmt.free(); return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه.' }); }
    const user = stmt.getAsObject();
    stmt.free();

    if (!(await bcrypt.compare(password, user.passwordHash))) {
        return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه.' });
    }
    const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username });
});

io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('لطفاً وارد شوید.'));
    try {
        socket.username = jwt.verify(token, process.env.JWT_SECRET).username;
        next();
    } catch { next(new Error('توکن نامعتبر.')); }
});

const onlineUsers = new Map();

function formatIranTime(date) {
    if (!date) return 'نامشخص';
    const d = new Date(date);
    return d.toLocaleString('fa-IR', { timeZone: 'Asia/Tehran', hour: '2-digit', minute: '2-digit', year: 'numeric', month: '2-digit', day: '2-digit' });
}

io.on('connection', (socket) => {
    const username = socket.username;
    onlineUsers.set(username, socket.id);

    db.run('UPDATE users SET lastSeen = ? WHERE username = ?', [new Date().toISOString(), username]);
    saveDB();

    io.emit('onlineUsers', Array.from(onlineUsers.keys()));
    broadcastUsersStatus();

    let messageCount = 0;
    let windowStart = Date.now();

    function checkRateLimit() {
        const now = Date.now();
        if (now - windowStart > RATE_WINDOW) {
            messageCount = 0;
            windowStart = now;
        }
        messageCount++;
        return messageCount <= MESSAGE_LIMIT;
    }

    const stmt = db.prepare('SELECT * FROM messages ORDER BY id DESC LIMIT 50');
    const msgs = [];
    while (stmt.step()) msgs.push(stmt.getAsObject());
    stmt.free();
    socket.emit('previousMessages', msgs.reverse());

    socket.on('getContacts', (callback) => {
        const s = db.prepare(`
            SELECT c.contactUsername as username, u.lastSeen
            FROM contacts c
            LEFT JOIN users u ON c.contactUsername = u.username
            WHERE c.owner = ?
        `);
        s.bind([username]);
        const contacts = [];
        while (s.step()) {
            const row = s.getAsObject();
            contacts.push({
                username: row.username,
                online: onlineUsers.has(row.username),
                lastSeen: onlineUsers.has(row.username) ? 'آنلاین' : formatIranTime(row.lastSeen)
            });
        }
        s.free();
        callback(contacts);
    });

    socket.on('addContact', (contactUsername, callback) => {
        if (!contactUsername || contactUsername === username) return callback({ error: 'نام کاربری معتبر نیست.' });
        const u = db.prepare('SELECT * FROM users WHERE username = ?');
        u.bind([contactUsername]);
        if (!u.step()) { u.free(); return callback({ error: 'کاربری با این نام وجود ندارد.' }); }
        u.free();

        const c = db.prepare('SELECT * FROM contacts WHERE owner = ? AND contactUsername = ?');
        c.bind([username, contactUsername]);
        if (c.step()) { c.free(); return callback({ error: 'این کاربر قبلاً در مخاطبین شماست.' }); }
        c.free();

        db.run('INSERT INTO contacts (owner, contactUsername) VALUES (?, ?)', [username, contactUsername]);
        saveDB();
        callback({ success: true });
    });

    socket.on('sendMessage', (text) => {
        if (!text || !text.trim()) return;
        if (!checkRateLimit()) return socket.emit('error', 'شما خیلی سریع پیام می‌فرستید. لطفاً کمی صبر کنید.');
        const clean = cleanText(text);
        if (!clean) return;
        const time = new Date().toLocaleTimeString('fa-IR');
        db.run('INSERT INTO messages (sender, text, time) VALUES (?, ?, ?)', [username, clean, time]);
        saveDB();
        io.emit('newMessage', { sender: username, text: clean, time });
    });

    socket.on('createGroup', ({ name, type, members }, callback) => {
        if (!name || !name.trim()) return callback({ error: 'نام گروه الزامی است.' });
        if (!members || members.length === 0) return callback({ error: 'حداقل یک عضو انتخاب کنید.' });

        const cleanName = cleanText(name);
        db.run('INSERT INTO groups (name, owner, type) VALUES (?, ?, ?)', [cleanName, username, type || 'group']);
        const groupId = db.exec('SELECT last_insert_rowid()')[0].values[0][0];

        db.run('INSERT INTO group_members (groupId, username, role) VALUES (?, ?, ?)', [groupId, username, 'admin']);
        members.forEach(m => {
            if (m !== username) {
                db.run('INSERT INTO group_members (groupId, username, role) VALUES (?, ?, ?)', [groupId, m, 'member']);
            }
        });
        saveDB();
        callback({ success: true, groupId, name: cleanName, type: type || 'group' });
    });

    socket.on('getMyGroups', (callback) => {
        const s = db.prepare(`SELECT g.* FROM groups g JOIN group_members gm ON g.id = gm.groupId WHERE gm.username = ?`);
        s.bind([username]);
        const groups = [];
        while (s.step()) groups.push(s.getAsObject());
        s.free();
        callback(groups);
    });

    socket.on('joinGroupRoom', (groupId) => socket.join(`group_${groupId}`));

    socket.on('getGroupMessages', (groupId, callback) => {
        const s = db.prepare('SELECT * FROM group_messages WHERE groupId = ? ORDER BY id DESC LIMIT 50');
        s.bind([groupId]);
        const msgs = [];
        while (s.step()) msgs.push(s.getAsObject());
        s.free();
        callback(msgs.reverse());
    });

    socket.on('sendGroupMessage', ({ groupId, text }) => {
        if (!text || !text.trim()) return;
        if (!checkRateLimit()) return socket.emit('error', 'شما خیلی سریع پیام می‌فرستید. لطفاً کمی صبر کنید.');
        const check = db.prepare('SELECT * FROM group_members WHERE groupId = ? AND username = ?');
        check.bind([groupId, username]);
        if (!check.step()) { check.free(); return; }
        check.free();

        const clean = cleanText(text);
        if (!clean) return;
        const time = new Date().toLocaleTimeString('fa-IR');
        db.run('INSERT INTO group_messages (groupId, sender, text, time) VALUES (?, ?, ?, ?)', [groupId, username, clean, time]);
        saveDB();
        io.to(`group_${groupId}`).emit('newGroupMessage', { groupId, sender: username, text: clean, time });
    });

    socket.on('disconnect', () => {
        onlineUsers.delete(username);
        db.run('UPDATE users SET lastSeen = ? WHERE username = ?', [new Date().toISOString(), username]);
        saveDB();
        io.emit('onlineUsers', Array.from(onlineUsers.keys()));
        broadcastUsersStatus();
    });
});

function broadcastUsersStatus() {
    const s = db.prepare('SELECT username, lastSeen FROM users');
    const users = [];
    while (s.step()) {
        const row = s.getAsObject();
        users.push({
            username: row.username,
            online: onlineUsers.has(row.username),
            lastSeen: onlineUsers.has(row.username) ? 'آنلاین' : formatIranTime(row.lastSeen)
        });
    }
    s.free();
    io.emit('usersStatus', users);
}

const PORT = process.env.PORT || 3000;
initDB().then(() => server.listen(PORT, () => console.log(`سرور LineChat روی پورت ${PORT}`)));
