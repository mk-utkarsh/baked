const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const SECRET_KEY = crypto.randomBytes(32).toString('hex'); //This genuinely aint anything.

const FLAG = process.env.FLAG || 'dbd{set_the_flag_env_var}'; //frenzyyy

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function sign(data) {
  return crypto.createHmac('sha256', SECRET_KEY).update(data).digest('hex');
}

function timingSafeEqual(a, b) {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

app.post('/register', (req, res) => {
  const { username } = req.body;

  if (!username || typeof username !== 'string') {
    return res.status(400).send('Username is required.');
  }
  if (username.length > 200) {
    return res.status(400).send('Username too long.');
  }

  const cookieData = `{"role": "guest", "username": "${username}"}`;

  const signature = sign(cookieData);
  const finalCookie = Buffer.from(cookieData).toString('base64') + '.' + signature;

  res.cookie('session', finalCookie, { httpOnly: false });
  res.redirect('/welcome');
});

app.get('/welcome', (req, res) => {
  res.send(`
    <html><body style="font-family: sans-serif; max-width: 600px; margin: 60px auto;">
      <h2>Welcome!</h2>
      <p>Your session cookie has been issued. Check your cookies, then try
      visiting <a href="/admin">/admin</a>.</p>
      <p><a href="/">&larr; back</a></p>
    </body></html>
  `);
});

app.get('/admin', (req, res) => {
  const session = req.cookies.session;
  if (!session) {
    return res.status(401).send('No session cookie. <a href="/">Register first</a>.');
  }

  const parts = session.split('.');
  if (parts.length !== 2) {
    return res.status(400).send('Malformed session cookie.');
  }

  const [encodedData, providedSignature] = parts;

  let cookieData;
  try {
    cookieData = Buffer.from(encodedData, 'base64').toString('utf8');
  } catch (e) {
    return res.status(400).send('Malformed session cookie.');
  }

  const expectedSignature = sign(cookieData);

  if (!timingSafeEqual(providedSignature, expectedSignature)) {
    return res.status(403).send('Invalid signature. Nice try.');
  }

  let parsed;
  try {
    parsed = JSON.parse(cookieData);
  } catch (e) {
    return res.status(400).send('Session data is not valid JSON.');
  }

  if (parsed.role === 'admin') {
    return res.send(`
      <html><body style="font-family: sans-serif; max-width: 600px; margin: 60px auto;">
        <h2>Welcome, admin.</h2>
        <p>Flag: <code>${FLAG}</code></p>
      </body></html>
    `);
  }

  return res.status(403).send(`
    <html><body style="font-family: sans-serif; max-width: 600px; margin: 60px auto;">
      <h2>Access denied</h2>
      <p>Your role is <code>${parsed.role}</code>, not <code>admin</code>.</p>
      <p><a href="/">&larr; back</a></p>
    </body></html>
  `);
});

app.listen(PORT, () => {
  console.log(`Half-Baked Cookies running on http://localhost:${PORT}`);
});
