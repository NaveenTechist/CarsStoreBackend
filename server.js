// server.js
const express = require('express');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const cors = require('cors'); 
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
app.use(cors({
  origin: 'http://localhost:3000',  // frontend URL
  methods: ['GET','POST','PUT','DELETE'],
  credentials: true,                // if you need cookies/auth
}));
app.use(express.json());

// -----------------------------
// MongoDB Connection
// -----------------------------
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected successfully'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// -----------------------------
// User Schema
// -----------------------------
const userSchema = new mongoose.Schema({
  name: String,
  imgUrl: String,
  rating: Number,
  review: Number,
  price: Number   
});

const User = mongoose.model('User', userSchema);

// -----------------------------
// Car Schema (for public API)
// -----------------------------
const carSchema = new mongoose.Schema({
  brand: String,
  model: String,
  price: Number,
}, { strict: false });  // 👈 allow existing hidden fields

const Car = mongoose.model('carsData', carSchema,'carsData'); // connect to carsData collection

// -----------------------------
// JWT Auth Middleware
// -----------------------------
function auth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ message: 'No token provided' });

  const [type, token] = header.split(' ');
  if (type !== 'Bearer' || !token) return res.status(401).json({ message: 'Invalid token format' });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ message: 'Token invalid or expired' });
  }
}

// -----------------------------
// Register API
// -----------------------------
app.post('/register', async (req, res) => {
  try {
    const {email, password, name, age } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'All fields required' });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ message: 'Email already registered' });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, age, email, password: hash });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name, age, email } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// -----------------------------
// Login API
// -----------------------------
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, age: user.age, email } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// -----------------------------
// Public Data API (MongoDB carsData)
// -----------------------------
app.get('/cars-data', async (req, res) => {
  try {
    const cars = await Car.find(); // fetch all cars from MongoDB
    res.json(cars);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// -----------------------------
// Private Data API
// -----------------------------
app.get('/api/data/private', auth, (req, res) => {
  res.json({ secret: `Hello user ${req.user.userId}, here’s your CarStore secret data 🚗` });
});

// -----------------------------
// Start Server
// -----------------------------
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`🚀 Server started at http://localhost:${port}`);
});
