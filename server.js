require('dotenv').config();
const path = require('path');
const express = require('express');
const app = express();
const session = require('express-session');
const db = require('./db');
const bcrypt = require('bcryptjs');
const PORT = process.env.PORT || 3000;
const { validation } = require('./utils-server/utils-server');
const { Server } = require('socket.io');
const http = require('http');
const server = http.createServer(app);
const io = new Server(server);
const { v4: uuidv4, validate } = require('uuid');
const middleware = require('./middleware.js');
const fs = require('fs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { XMLParser } = require('fast-xml-parser');

const AUTH_ERROR_MSG = 'Invalid email or password.';
const SERVER_ERROR_MSG = 'A server error occurred. Please try again later.';
const USER_NOT_FOUND = 'User not found';

app.use(express.json());
app.use(express.text({ type: 'application/xml' }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: false,
    httpOnly: false,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.use(express.static('./public'));

const adminRoute = require('./admin-routes/admin-routes.js');
const { type } = require('os');

app.use('/', adminRoute);

io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  socket.on('join', (userId) => {
    if (!userId) {
      console.log('Error: Attempt to join room with null ID');
      return;
    }
    socket.join(`user_${userId}`);
    console.log(`User ${userId} joined their private room`);
  });

  socket.on('disconnect', () => {
    console.log("User disconnected");
  });
});

function wafCheck(req, res, next) {
    const rawXml = req.body || '';
    const blackList = /UNION|SELECT|FROM/i;

    if (blackList.test(rawXml)) {
        return res.status(403).send('<h1>403 Forbidden: WAF Flagged Potential Attack</h1>');
    }
    next();
}

app.post('/register', async (req, res) => {
  let { username, email, password } = req.body;

  const usernameRes = validation.isValidUsername(username);
  if (!usernameRes.valid) return res.status(400).json({ error: usernameRes.error });

  const emailRes = validation.isValidEmail(email);
  if (!emailRes.valid) return res.status(400).json({ error: emailRes.error });

  const passwordRes = validation.isValidPassword(password);
  if (!passwordRes.valid) return res.status(400).json({ error: passwordRes.error });

  const userId = uuidv4();
  username = usernameRes.value;
  email = emailRes.value;
  password = passwordRes.value;
  const hashedPassword = await bcrypt.hash(password, 10);

  const sqlQuery = `
    INSERT INTO users (user_id, username, email, password)
    VALUES ($1, $2, $3, $4)
    RETURNING user_id;
  `;
  const values = [userId, username, email, hashedPassword];

  try {
    const result = await db.query(sqlQuery, values);

    return res.json({
      message: 'Success! User is created!',
      id: result.rows[0].user_id
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'User with this email or username already exists.' });
    }
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
})

const mfaLimiter = rateLimit({
  windowMs: 2 * 60 * 1000,
  max: 5,
  statusCode: 429,
  message: { error: 'Too many 2FA attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

app.post('/check-code2fa', mfaLimiter, async (req, res) => {
  let { userCode } = req.body;

  if (typeof userCode != 'string') {
    return res.status(400).json({ error: 'Code incorrect or invalid format!' });
  }
  userCode = userCode.trim();

  if (!/^\d{4}$/.test(userCode)) {
    return res.status(400).json({ error: 'Code incorrect or invalid format!' });
  }
  if (!req.session.correct2faCode || !req.session.tempUserID) {
    return res.status(400).json({ error: 'Session expired or invalid. Please login again.' });
  }
  if (req.session.correct2faCode !== userCode) {
    req.session.mfaAttempts = (req.session.mfaAttempts || 0) + 1;
    if (req.session.mfaAttempts >= 5) {
      return req.session.destroy(err => {
        if (err) {
          console.error('Failed close session, ', err.message);
          return res.status(500).json({ error: SERVER_ERROR_MSG });
        }
        res.clearCookie('connect.sid');
        return res.json('Too many 2FA attempts. Please try again later.');
      })
    }
    return res.status(401).json({ error: 'Code incorrect.' });
  }
  const sqlQuery = `SELECT user_id, username, email, role FROM users WHERE user_id = $1;`;

  try {
    const result = await db.query(sqlQuery, [req.session.tempUserID]);
    const user = result.rows[0];

    if (result.rows.length === 0) {
      throw new Error(USER_NOT_FOUND);
    }
    if (req.session.stayLoggedIn === true) {
      const SECRET_KEY = process.env.SESSION_SECRET || 'super_secret_key_123';
      const days = 30;
      const expiryTime = Date.now() + (days * 24 * 60 * 60 * 1000);
      const hmac = crypto.createHmac('sha256', SECRET_KEY);
      hmac.update(`${user.email}:${expiryTime}`);
      const signature = hmac.digest('hex');
      const rawCookieValue = `${user.email}:${expiryTime}:${signature}`;
      const secureCookie = Buffer.from(rawCookieValue).toString('base64');

      res.cookie('remember_me', secureCookie, {
        maxAge:  days * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: false,
        sameSite: 'strict'
      });
    }
    req.session.userID = req.session.tempUserID;
    req.session.username = user.username;
    req.session.role = user.role;

    delete req.session.tempUserID;
    delete req.session.correct2faCode;
    delete req.session.mfaAttempts;

    return res.json({
      message: "Welcome!",
      user: user.username
    });
  } catch (err) {
    console.log('Failed check 2FA, ', err.message);
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
})

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  statusCode: 429,
  message: { error: 'Too many login attempts. Pleasy try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

app.post('/login', loginLimiter, async (req, res) => {
  let { email, password, stayLoggedIn } = req.body;

  const emailRes = validation.isValidEmail(email);
  if (!emailRes.valid) return res.status(400).json({ error: emailRes.error });

  const passwordRes = validation.isValidPassword(password);
  if (!passwordRes.valid) return res.status(400).json({ error: passwordRes.error });

  const cleanEmail = emailRes.value;
  const cleanPassword = passwordRes.value;

  const sqlQuery = `SELECT * FROM users WHERE email = $1;`;

  try {
    const result = await db.query(sqlQuery, [cleanEmail]);

    if (result.rows.length === 0) {
      const fakeHash = '$2b$10$s6eA28lQfeDZkJTVPRTtGeWJYQ2jpJDZIiNLVnPDaEfiWfg0sk25e';
      await bcrypt.compare(cleanPassword, fakeHash);
      return res.status(400).json({ error: AUTH_ERROR_MSG });
    }
    const user = result.rows[0];

    const isMatchPassword = await bcrypt.compare(cleanPassword, user.password);

    if (!isMatchPassword) {
      return res.status(400).json({ error: AUTH_ERROR_MSG });
    }
    const generatedCode = String(crypto.randomInt(0, 10000)).padStart(4, '0');
    console.log(generatedCode);

    req.session.correct2faCode = generatedCode;
    req.session.tempUserID = user.user_id;
    req.session.stayLoggedIn = !!stayLoggedIn;
    // req.session.password = cleanPassword;

    return res.json({ message: 'MFA_REQUIRED' });

  } catch (err) {
      console.error('Failed login, ', err.message);
      return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
})

app.get('/login2', (req, res) => {
  return res.sendFile(path.join(__dirname, 'private', 'login2.html'));
})

// open access for profile.html
app.get('/profile', middleware.checkAuth, (req, res) => {
  return res.sendFile(path.join(__dirname, 'private', 'profile.html'));
})

app.get('/api/profile', middleware.checkAuth, async (req, res) => {
  if (!req.query.id) {
    try {
      const sqlQuery = `
        SELECT user_id, username, email, role, bio
        FROM users WHERE user_id = $1;
      `;
      const result = await db.query(sqlQuery, [req.session.userID]);

      if (result.rows.length === 0) {
        throw new Error(USER_NOT_FOUND);
      }
      const user = result.rows[0];

      return res.json({
        id: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role,
        bio: user.bio
      });
    } catch (err) {
      console.error(err.message);
      return res.status(500).json({ error: SERVER_ERROR_MSG });
    }
  } else {
    try {
      const id = req.query.id;
      const sqlQuery = `
        SELECT user_id, username, email, role
        FROM users WHERE username = $1;
      `;
      const result = await db.query(sqlQuery, [id]);

      if (result.rows.length === 0) {
        throw new Error(USER_NOT_FOUND);
      }
      const user = result.rows[0];

      return res.json({
        id: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role
      });
    } catch (err) {
      console.error('Failed profile search:', err.message);
      return res.status(500).json({ error: SERVER_ERROR_MSG });
    }
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Could not log out.' });
    }
    res.clearCookie('connect.sid');
    return res.json({ message: 'Logged out successfuly.' });
  })
})

app.put('/change-username', middleware.checkAuth, async (req, res) => {
  let { username } = req.body;

  const usernameRes = validation.isValidUsername(username);
  if (!usernameRes.valid) return res.status(400).json({ message: usernameRes.error });
  const cleanUsername = usernameRes.value;

  try {
    const sqlUpdateUsername = `
      UPDATE users SET username = $1
      WHERE user_id = $2 RETURNING username;
    `;
    const result = await db.query(sqlQuery, [sqlUpdateUsername, req.session.userID]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: USER_NOT_FOUND });
    }
    const user = result.rows[0];
    req.session.username = user.username;

    return res.json({
      message: 'Username updated successful!',
      username: user.username
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Username already exists.' });
    }
    console.error('Failed change username, ', err.message);
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
})

app.put('/change-email', middleware.checkAuth, async (req, res) => {
  let { email } = req.body;

  const emailRes = validation.isValidEmail(email);
  if (!emailRes.valid) return res.status(400).json({ error: emailRes.error });
  const cleanEmail = emailRes.value;

  try {
    const sqlUpdateEmail = `UPDATE users SET email = $1 WHERE user_id = $2 RETURNING email;`;
    const result = await db.query(sqlUpdateEmail, [cleanEmail, req.session.userID]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: USER_NOT_FOUND });
    }
    const user = result.rows[0];

    return res.json({
      message: 'Email updated successful!',
      email: user.email
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Email already exists.' });
    }
    console.error('Failed change email, ', err.message);
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
})

// change password
app.put('/change-password', middleware.checkAuth, async (req, res) => {
  const { currPassword, newPassword1, newPassword2 } = req.body;

  const currPasswordRes = validation.isValidPassword(currPassword);
  const newPassword1Res = validation.isValidPassword(newPassword1);
  const newPassword2Res = validation.isValidPassword(newPassword2);

  if (!currPasswordRes.valid || !newPassword1Res.valid || !newPassword2Res.valid) {
    return res.status(400).json({ error: 'Invalid password format!' });
  }
  const cleanCurrPassword = currPasswordRes.value;
  const cleanNewPassword1 = newPassword1Res.value;
  const cleanNewPassword2 = newPassword2Res.value;

  if (cleanNewPassword1 !== cleanNewPassword2) {
    return res.status(400).json({ error: "New passwords mismatch." });
  }
  try {
    const sqlFindUser = `SELECT password FROM users WHERE user_id = $1;`;
    const result = await db.query(sqlFindUser, [req.session.userID]);

    if (result.rows.length === 0) {
      throw new Error(USER_NOT_FOUND);
    }
    const user = result.rows[0];

    const isCurrPassword = await bcrypt.compare(cleanCurrPassword, user.password);
    if (!isCurrPassword) return res.status(401).json({ error: 'Current password incorrect' });
    const hashedPassword = await bcrypt.hash(cleanNewPassword1, 10);

    const sqlUpdatePass = `UPDATE users SET password = $1 WHERE user_id = $2;`;
    await db.query(sqlQuery, [sqlUpdatePass, req.session.userID]);

    return res.json({ message: 'Password updated successfully!' });

  } catch (err) {
    console.error('Failed change password, ', err.message);
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
})

app.delete('/delete-account', middleware.checkAuth, async (req, res) => {
  const { password } = req.body;

  const passwordRes = validation.isValidPassword(password);
  if (!passwordRes.valid) return res.status(400).json({ error: passwordRes.error });
  const cleanPassword = passwordRes.value;

  try {
    const sqlCheckCurrPass = `SELECT password FROM users WHERE user_id = $1;`;
    const result = await db.query(sqlCheckCurrPass, [req.session.userID]);

    if (result.rows.length === 0) {
      throw new Error(USER_NOT_FOUND);
    }
    const user = result.rows[0];

    const isPassword = await bcrypt.compare(cleanPassword, user.password);
    if (!isPassword) return res.status(401).json({ error: 'Password incorrect' });

    const sqlDeleteAcc = `DELETE FROM users WHERE user_id = $1`;
    await db.query(sqlDeleteAcc, [req.session.userID]);

    req.session.destroy((err) => {
      if (err) {
        console.error('Failed delete account session cleanup: ', err.message);
        return res.status(500).json({ error: SERVER_ERROR_MSG });
      }
      res.clearCookie('connect.sid');
      return res.json({ message: 'Account deleted successful!' });
    });
  } catch (err) {
    console.log('Failed password to delete account, ', err.message);
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
})

// search users
app.post('/api/search-user', middleware.checkAuth, async (req, res) => {
  const { username } = req.body;

  const usernameRes = validation.isValidUsername(username);
  if (!usernameRes.valid) return res.status(400).json({ message: usernameRes.error });
  const cleanUsername = usernameRes.value;

  try {
    const sqlSearchUsers = `
      SELECT user_id, username FROM users
      WHERE username = $1 AND user_id != $2;
    `;
    const result = await db.query(sqlSearchUsers, [cleanUsername, req.session.userID]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found!' });
    }
    const user = result.rows[0];

    return res.json({
      id: user.user_id,
      username: user.username
    });
  } catch (err) {
    console.error('Failed search users, ', err.message);
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
})

app.post('/api/send-message', middleware.checkAuth, async (req, res) => {
  const { receiver_id, content } = req.body;
  const sender_id = req.session.userID;

  const contentRes = validation.isValidMessage(content);
  if (!contentRes.valid) return res.status(400).json({ error: contentRes.error });
  const cleanContent = contentRes.value;

  try {
    const sqlSendMessage = `
      INSERT INTO messages (sender_id, receiver_id, content)
      VALUES ($1, $2, $3)
      RETURNING message_id, sent_at;
    `;
    const result = await db.query(sqlSendMessage, [sender_id, receiver_id, cleanContent]);
    const savedMessage = result.rows[0];

    const newMessage = {
      message_id: savedMessage.message_id,
      sender_id: sender_id,
      receiver_id: receiver_id,
      content: cleanContent,
      sent_at: savedMessage.sent_at
    };
    io.to(`user_${receiver_id}`).emit('new_message', newMessage);
    io.to(`user_${sender_id}`).emit('new_message', newMessage);

    return res.json({ message: 'Message sent successfully!' });

  } catch (err) {
    if (err.code === '23503') {
      return res.status(404).json({ error: 'Receiver user not found.' });
    }
    console.error("Failed send message, ", err.message);
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
});

// show messages
app.get('/api/messages/:otherId', middleware.checkAuth, async (req, res) => {
  const myId = req.session.userID;
  const otherId = req.params.otherId;

  try {
    const sqlShowMessages = `
      SELECT * FROM messages
      WHERE (sender_id = $1 AND receiver_id = $2)
      OR (sender_id = $2 AND receiver_id = $1)
      ORDER BY sent_at ASC;
    `;
    const result = await db.query(sqlShowMessages, [myId, otherId]);
    return res.json(result.rows);

  } catch (err) {
    if (err.code === '22P02') {
      return res.status(400).json({
        error: 'Invalid user ID format!'
      });
    }
    console.error("Failed show message, ", err.message);
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
});

app.get('/admin-panel', middleware.isAdmin, (req, res) => {
  return res.sendFile(path.join(__dirname, 'private', 'admin-panel.html'));
})

app.post('/get-transcript', async (req, res) => {
  const senderId = req.session.userID;
  const { receiverId } = req.body;

  try {
    const sqlGetTranscript = `
      SELECT content FROM messages
      WHERE sender_id = $1 AND receiver_id = $2
      OR sender_id = $2 AND receiver_id = $1
      ORDER BY sent_at ASC;
    `;
    const result = await db.query(sqlGetTranscript, [senderId, receiverId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No messages found!' });
    }
    const chatContent = result.rows.map(row => row.content).join('\n');
    const transcriptsName = uuidv4();
    const pathFile = `./chats/${transcriptsName}.txt`;

    res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition');

    fs.writeFile(pathFile, chatContent, 'utf-8', (err) => {
      res.download(pathFile, `transcript-${transcriptsName}.txt`, (downloadErr) => {
        if (downloadErr) console.log('Download error: ', downloadErr);
        fs.unlink(pathFile, () => {});
      })
    })
  } catch (err) {
    if (err.code === '22P02') {
      return res.status(400).json({ error: 'Invalid user ID format.' });
    }
    console.error('Failed get transcript, ', err.message);
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
});

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const emailRes = validation.isValidEmail(email);
  if (!emailRes.valid) return res.status(400).json({ error: emailRes.error });
  const cleanEmail = emailRes.value;

  try {
    const sqlFindUser = `SELECT user_id, email FROM users WHERE email = $1`;
    const foundUser = await db.query(sqlFindUser, [cleanEmail]);

    if (foundUser.rows.length === 0) {
      return res.json({
        message: 'If this email exists, a reset link has been generated.'
      });
    }
    const userId = foundUser.rows[0].user_id;

    const sqlInvalidateOldTokens = `
      UPDATE password_resets
      SET used = 2
      WHERE user_id = $1 AND used = 0;
    `;
    await db.query(sqlInvalidateOldTokens, [userId]);

    const generatedToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(generatedToken).digest('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    const sqlInsert = `
      INSERT INTO password_resets (user_id, token, expires_at)
      VALUES ($1, $2, $3);
    `;
    await db.query(sqlInsert, [userId, hashedToken, expiresAt]);

    return res.json({
      message: `Link for reset password`,
      link: `/reset-password.html?token=${generatedToken}`
    });

  } catch (err) {
    console.error('Failed forgot password, ', err.message);
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
});

app.put('/reset-password', async (req, res) => {
  const { password_1, password_2, token } = req.body;

  if (!token) return res.status(400).json({ error: 'Token is missing' });
  const newPassword1Res = validation.isValidPassword(password_1);
  const newPassword2Res = validation.isValidPassword(password_2);

  if (!newPassword1Res.valid || !newPassword2Res.valid) {
    return res.status(400).json({ error: 'Invalid password format!' });
  }

  const cleanPassword1 = newPassword1Res.value;
  const cleanPassword2 = newPassword2Res.value;

  if (cleanPassword1 !== cleanPassword2) {
    return res.status(400).json({ error: 'New passwords mismatch.' });
  }

  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

  try {
    const sqlCheckTokenSql = `
      SELECT user_id FROM password_resets
      WHERE token = $1 AND expires_at > NOW() AND used = 0;
    `;
    const result = await db.query(sqlCheckTokenSql, [hashedToken]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token.' });
    }
    const userId = result.rows[0].user_id;

    const encryptedPassword = await bcrypt.hash(cleanPassword1, 10);

    const sqlUpdatePassword = `UPDATE users SET password = $1 WHERE user_id = $2`;
    await db.query(sqlUpdatePassword, [encryptedPassword, userId]);

    const sqlInvalidateToken = `UPDATE password_resets SET used = 1 WHERE token = $1;`;
    await db.query(sqlInvalidateToken, [hashedToken]);

    return res.json({ message: 'Password successfully reset. You can log in now.' });

  } catch (err) {
    console.log('Failed to reset password:', err.message);
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
});

app.put('/update-bio', middleware.checkAuth, async (req, res) => {
  if (!req.session.userID) return res.status(401).json({ error: 'Unauthorized' });

  let { bio } = req.body;

  if (typeof bio !== 'string') return res.status(400).json({ error: 'Invalid format.' });
  bio = bio.trim();
  if (bio.length > 300) return res.status(400).json({ error: 'Bio is too long.' });

  try {
    const sqlUpdateBio = `UPDATE users SET bio = $1 WHERE user_id = $2;`;
    await db.query(sqlUpdateBio, [bio, req.session.userID]);

    return res.json({ message: 'Bio updated successfully!' });

  } catch (err) {
    console.error('Failed update bio, ', err.message);
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
});

app.post('/api/feed', middleware.checkAuth, async (req, res) => {
  const { message } = req.body;
  const username = req.session.username;

  if (!message || message.trim() === '') {
    return res.status(400).json({ error: 'Message cannot be empty.' });
  }
  const cleanMessage = message.trim();

  try {
    const sqlInsertPost = `INSERT INTO feed_posts (username, message) VALUES ($1, $2);`;
    await db.query(sqlInsertPost, [username, cleanMessage]);

    return res.json({ message: 'Post added successfully.' });

  } catch (err) {
    console.error('Failed feed (post), ', err.message);
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
});

app.get('/api/feed', async (req, res) => {
  try {
    const sqlShowPosts = `
      SELECT username, message, created_at
      FROM feed_posts
      ORDER BY post_id DESC;
    `;
    const result = await db.query(sqlShowPosts);

    return res.json(result.rows);

  } catch (err) {
    console.error('Failed feed (get), ', err.message);
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
});

app.get('/api/avatars', async (req, res) => {
  try {
    const gender = req.query.gender || 'all';
    let sqlGetAvatar;
    let param = [];

    if (gender === 'all') {
      sqlGetAvatar = `SELECT * FROM avatars WHERE is_premium = FALSE;`;
    } else {
      sqlGetAvatar = `
        SELECT * FROM avatars
        WHERE gender = $1 AND is_premium = FALSE;
      `;
      param = [gender];
    }
    const result = await db.query(sqlGetAvatar, param);

    return res.json(result.rows);

  } catch (err) {
    console.error('Failed get avatars:', err.message);
    return res.status(500).json({ error: SERVER_ERROR_MSG });
  }
});

app.post('/product/stock', wafCheck, async (req, res) => {
  try {
    const parser = new XMLParser({ htmlEntities: true });
    const jsonObj = parser.parse(req.body);

    const storeId = jsonObj.stockCheck.storeId;
    const productId = jsonObj.stockCheck.productId;

    const query = `
      SELECT units FROM store_stock
      WHERE product_id = ${productId} AND store_id = ${storeId}
    `;
    const result = await db.query(query, [productId, storeId]);

    if (!result.rows || result.rows.length === 0) {
        return res.send('<response><units>0</units></response>');
    }
    const firstCell = Object.values(result.rows[0])[0];
    res.send(`<response><units>${firstCell}</units></response>`);
  } catch (err) {
      console.error('[!] ERROR! "/product/stock":', err.message);
      res.status(500).send('<response><error>Internal Error</error></response>');
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log(`SERVER is running on http://localhost:${PORT} successfully`);
});
