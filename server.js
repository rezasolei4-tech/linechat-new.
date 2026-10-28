require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const sanitizeHtml = require('sanitize-html');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.json());
app.use(express.static('public'));

// اتصال به دیتابیس Supabase
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const MESSAGE_LIMIT = 20;
const RATE_WINDOW = 60000;

async function initDB() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            passwordHash TEXT NOT NULL,
            lastSeen TIMESTAMPTZ
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            sender TEXT NOT NULL,
            text TEXT NOT NULL,
            time TEXT NOT NULL
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS groups (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            owner TEXT NOT NULL,
            type TEXT DEFAULT 'group',
            createdAt TIMESTAMPTZ DEFAULT NOW()
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS group_members (
            id SERIAL PRIMARY KEY,
            groupId INTEGER NOT NULL,
            username TEXT NOT NULL,
            role TEXT DEFAULT 'member'
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS group_messages (
            id SERIAL PRIMARY KEY,
            groupId INTEGER NOT NULL,
            sender TEXT NOT NULL,
            text TEXT NOT NULL,
            time TEXT NOT NULL
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS contacts (
            id SERIAL PRIMARY KEY,
            owner TEXT NOT NULL,
            contactUsername TEXT NOT NULL,
            UNIQUE(owner, contactUsername)
        )
    `);
    console.log('دیتابیس Supabase آماده شد.');
}

function cleanText(text) {
    return sanitizeHtml(text, { allowedTags: [], allowedAttributes: {} }).trim();
}

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'همه فیلدها الزامی است.' });
    if (password.length < 4) return res.status(400).json({ error: 'رمز حداقل ۴ کاراکتر.' });

    const existing = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'نام کاربری تکراری است.' });

    const hash = await bcrypt.hash(password, 12);
    await pool.query('INSERT INTO users (username, passwordHash) VALUES ($1, $2)', [username, hash]);
    res.json({ success: true });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه.' });
    const user = result.rows[0];

    if (!(await bcrypt.compare(password, user.passwordhash))) {
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

io.on('connection', async (socket) => {
    const username = socket.username;
    onlineUsers.set(username, socket.id);

    await pool.query('UPDATE users SET lastSeen = $1 WHERE username = $2', [new Date().toISOString(), username]);

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

    const msgsResult = await pool.query('SELECT * FROM messages ORDER BY id DESC LIMIT 50');
    socket.emit('previousMessages', msgsResult.rows.reverse());

    socket.on('getContacts', async (callback) => {
        const result = await pool.query(`
            SELECT c.contactUsername as username, u.lastSeen
            FROM contacts c
            LEFT JOIN users u ON c.contactUsername = u.username
            WHERE c.owner = $1
        `, [username]);
        const contacts = result.rows.map(row => ({
            username: row.username,
            online: onlineUsers.has(row.username),
            lastSeen: onlineUsers.has(row.username) ? 'آنلاین' : formatIranTime(row.lastseen)
        }));
        callback(contacts);
    });

    socket.on('addContact', async (contactUsername, callback) => {
        if (!contactUsername || contactUsername === username) return callback({ error: 'نام کاربری معتبر نیست.' });
        const userCheck = await pool.query('SELECT * FROM users WHERE username = $1', [contactUsername]);
        if (userCheck.rows.length === 0) return callback({ error: 'کاربری با این نام وجود ندارد.' });

        const check = await pool.query('SELECT * FROM contacts WHERE owner = $1 AND contactUsername = $2', [username, contactUsername]);
        if (check.rows.length > 0) return callback({ error: 'این کاربر قبلاً در مخاطبین شماست.' });

        await pool.query('INSERT INTO contacts (owner, contactUsername) VALUES ($1, $2)', [username, contactUsername]);
        callback({ success: true });
    });

    socket.on('sendMessage', async (text) => {
        if (!text || !text.trim()) return;
        if (!checkRateLimit()) return socket.emit('error', 'شما خیلی سریع پیام می‌فرستید. لطفاً کمی صبر کنید.');
        const clean = cleanText(text);
        if (!clean) return;
        const time = new Date().toLocaleTimeString('fa-IR');
        await pool.query('INSERT INTO messages (sender, text, time) VALUES ($1, $2, $3)', [username, clean, time]);
        io.emit('newMessage', { sender: username, text: clean, time });
    });

    socket.on('createGroup', async ({ name, type, members }, callback) => {
        if (!name || !name.trim()) return callback({ error: 'نام گروه الزامی است.' });
        if (!members || members.length === 0) return callback({ error: 'حداقل یک عضو انتخاب کنید.' });

        const cleanName = cleanText(name);
        const groupResult = await pool.query('INSERT INTO groups (name, owner, type) VALUES ($1, $2, $3) RETURNING id', [cleanName, username, type || 'group']);
        const groupId = groupResult.rows[0].id;

        await pool.query('INSERT INTO group_members (groupId, username, role) VALUES ($1, $2, $3)', [groupId, username, 'admin']);
        for (const m of members) {
            if (m !== username) {
                await pool.query('INSERT INTO group_members (groupId, username, role) VALUES ($1, $2, $3)', [groupId, m, 'member']);
            }
        }
        callback({ success: true, groupId, name: cleanName, type: type || 'group' });
    });

    socket.on('getMyGroups', async (callback) => {
        const result = await pool.query(`SELECT g.* FROM groups g JOIN group_members gm ON g.id = gm.groupId WHERE gm.username = $1`, [username]);
        callback(result.rows);
    });

    socket.on('joinGroupRoom', (groupId) => socket.join(`group_${groupId}`));

    socket.on('getGroupMessages', async (groupId, callback) => {
        const result = await pool.query('SELECT * FROM group_messages WHERE groupId = $1 ORDER BY id DESC LIMIT 50', [groupId]);
        callback(result.rows.reverse());
    });

    socket.on('sendGroupMessage', async ({ groupId, text }) => {
        if (!text || !text.trim()) return;
        if (!checkRateLimit()) return socket.emit('error', 'شما خیلی سریع پیام می‌فرستید. لطفاً کمی صبر کنید.');
        const check = await pool.query('SELECT * FROM group_members WHERE groupId = $1 AND username = $2', [groupId, username]);
        if (check.rows.length === 0) return;

        const clean = cleanText(text);
        if (!clean) return;
        const time = new Date().toLocaleTimeString('fa-IR');
        await pool.query('INSERT INTO group_messages (groupId, sender, text, time) VALUES ($1, $2, $3, $4)', [groupId, username, clean, time]);
        io.to(`group_${groupId}`).emit('newGroupMessage', { groupId, sender: username, text: clean, time });
    });

    socket.on('disconnect', async () => {
        onlineUsers.delete(username);
        await pool.query('UPDATE users SET lastSeen = $1 WHERE username = $2', [new Date().toISOString(), username]);
        io.emit('onlineUsers', Array.from(onlineUsers.keys()));
        broadcastUsersStatus();
    });
});

async function broadcastUsersStatus() {
    const result = await pool.query('SELECT username, lastSeen FROM users');
    const users = result.rows.map(row => ({
        username: row.username,
        online: onlineUsers.has(row.username),
        lastSeen: onlineUsers.has(row.username) ? 'آنلاین' : formatIranTime(row.lastseen)
    }));
    io.emit('usersStatus', users);
}

const PORT = process.env.PORT || 3000;
initDB().then(() => server.listen(PORT, () => console.log(`سرور LineChat روی پورت ${PORT}`)));
