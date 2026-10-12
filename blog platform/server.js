require('dotenv').config();
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const { MONGODB_URI, JWT_SECRET } = process.env;
if (!MONGODB_URI || !JWT_SECRET) { console.error('Set MONGODB_URI and JWT_SECRET in .env'); process.exit(1); }

const app = express();
app.use(express.json({ limit: '200kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const { ObjectId } = mongoose.Types;
const validId = id => mongoose.isValidObjectId(id);

// ---------- Models ----------
const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 60 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
}));
const Post = mongoose.model('Post', new mongoose.Schema({
  author: { type: ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true, trim: true, maxlength: 150 },
  body: { type: String, required: true, maxlength: 20000 },
  commentCount: { type: Number, default: 0 },
}, { timestamps: true }));
const Comment = mongoose.model('Comment', new mongoose.Schema({
  post: { type: ObjectId, ref: 'Post', required: true, index: true },
  author: { type: ObjectId, ref: 'User', required: true },
  text: { type: String, required: true, trim: true, maxlength: 1000 },
}, { timestamps: true }));

// ---------- Auth ----------
const sign = u => jwt.sign({ id: u._id }, JWT_SECRET, { expiresIn: '7d' });
const publicUser = u => ({ id: u._id, name: u.name, email: u.email });

async function auth(req, res, next) {
  try {
    const { id } = jwt.verify((req.get('authorization') || '').replace('Bearer ', ''), JWT_SECRET);
    req.user = await User.findById(id);
    req.user ? next() : res.status(401).json({ error: 'Please log in again.' });
  } catch { res.status(401).json({ error: 'Please log in again.' }); }
}

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
app.post('/api/auth/register', limiter, async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !/^\S+@\S+\.\S+$/.test(email || '')) return res.status(400).json({ error: 'Enter a name and a valid email.' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (await User.findOne({ email: email.toLowerCase() })) return res.status(409).json({ error: 'That email is already registered.' });
  const user = await User.create({ name, email, password: await bcrypt.hash(password, 10) });
  res.status(201).json({ token: sign(user), user: publicUser(user) });
});
app.post('/api/auth/login', limiter, async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email || '').toLowerCase() });
  if (!user || !(await bcrypt.compare(req.body.password || '', user.password)))
    return res.status(401).json({ error: 'Wrong email or password.' });
  res.json({ token: sign(user), user: publicUser(user) });
});
app.get('/api/auth/me', auth, (req, res) => res.json(publicUser(req.user)));

// ---------- Posts ----------
const escRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const PAGE = 10;

app.get('/api/posts', async (req, res) => {
  const f = {};
  if (req.query.q) { const re = new RegExp(escRe(String(req.query.q)), 'i'); f.$or = [{ title: re }, { body: re }]; }
  if (validId(req.query.author)) f.author = req.query.author;
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const [posts, total] = await Promise.all([
    Post.find(f).sort({ createdAt: -1 }).skip((page - 1) * PAGE).limit(PAGE).populate('author', 'name').lean(),
    Post.countDocuments(f),
  ]);
  res.json({ total, hasMore: page * PAGE < total, posts: posts.map(p => ({ ...p, excerpt: p.body.slice(0, 220), body: undefined })) });
});

app.get('/api/posts/:id', async (req, res) => {
  const p = validId(req.params.id) && await Post.findById(req.params.id).populate('author', 'name');
  p ? res.json(p) : res.status(404).json({ error: 'Post not found.' });
});

app.post('/api/posts', auth, async (req, res) => {
  try { res.status(201).json(await Post.create({ title: req.body.title, body: req.body.body, author: req.user._id })); }
  catch { res.status(400).json({ error: 'A title and some content are required.' }); }
});

app.put('/api/posts/:id', auth, async (req, res) => {          // only the author can edit
  try {
    const p = validId(req.params.id) && await Post.findOneAndUpdate(
      { _id: req.params.id, author: req.user._id }, { title: req.body.title, body: req.body.body }, { new: true, runValidators: true });
    p ? res.json(p) : res.status(404).json({ error: 'Post not found, or it is not yours.' });
  } catch { res.status(400).json({ error: 'A title and some content are required.' }); }
});

app.delete('/api/posts/:id', auth, async (req, res) => {       // only the author can delete (comments go too)
  const p = validId(req.params.id) && await Post.findOneAndDelete({ _id: req.params.id, author: req.user._id });
  if (!p) return res.status(404).json({ error: 'Post not found, or it is not yours.' });
  await Comment.deleteMany({ post: p._id });
  res.json({ ok: true });
});

// ---------- Comments ----------
app.get('/api/posts/:id/comments', async (req, res) => {
  if (!validId(req.params.id)) return res.json([]);
  res.json(await Comment.find({ post: req.params.id }).sort({ createdAt: 1 }).populate('author', 'name'));
});

app.post('/api/posts/:id/comments', auth, async (req, res) => {
  const post = validId(req.params.id) && await Post.findById(req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found.' });
  const text = String(req.body.text || '').trim();
  if (!text) return res.status(400).json({ error: 'Write something before posting.' });
  const c = await Comment.create({ post: post._id, author: req.user._id, text });
  await Post.updateOne({ _id: post._id }, { $inc: { commentCount: 1 } });
  res.status(201).json(await c.populate('author', 'name'));
});

app.delete('/api/comments/:id', auth, async (req, res) => {    // comment author OR the post's author can remove it
  const c = validId(req.params.id) && await Comment.findById(req.params.id);
  if (!c) return res.status(404).json({ error: 'Comment not found.' });
  const post = await Post.findById(c.post);
  const allowed = c.author.equals(req.user._id) || post?.author.equals(req.user._id);
  if (!allowed) return res.status(403).json({ error: 'You cannot delete this comment.' });
  await c.deleteOne();
  if (post) await Post.updateOne({ _id: post._id }, { $inc: { commentCount: -1 } });
  res.json({ ok: true });
});

mongoose.connect(MONGODB_URI).then(() => {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`http://localhost:${port}`));
}).catch(e => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
