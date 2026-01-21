# Blue-Port-Courier-
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

require('dotenv').config();
const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  customerId: String,
  address: String,
  role: { type: String, default: "customer" },
});

const PackageSchema = new mongoose.Schema({
  trackingNumber: String,
  customerId: String,
  status: String,
  paymentMethod: String,
  createdAt: { type: Date, default: Date.now },
});

const TrackingSchema = new mongoose.Schema({
  trackingNumber: String,
  status: String,
  location: String,
  timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model("User", UserSchema);
const Package = mongoose.model("Package", PackageSchema);
const Tracking = mongoose.model("Tracking", TrackingSchema);

const generateCustomerId = () => `BP-${Math.floor(10000 + Math.random() * 90000)}`;

const auth = (role) => (req, res, next) => {
  try {
    const token = req.headers.authorization.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    if (role && decoded.role !== role) return res.status(403).json({ message: "Forbidden" });
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Unauthorized" });
  }
};

// Signup
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const customerId = generateCustomerId();
  const address = `Name: ${name}\nCompany: BluePort Courier\nCustomer ID: ${customerId}\nWarehouse: 14 Logistics Park\nKingston, Jamaica`;
  const user = await User.create({ name, email, password: hashed, customerId, address });
  res.json({ message: "Account created", address });
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: "User not found" });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ message: "Wrong password" });
  const token = jwt.sign({ id: user._id, role: user.role, customerId: user.customerId }, JWT_SECRET);
  res.json({ token, role: user.role });
});

// Admin add package
app.post("/api/admin/package", auth("admin"), async (req, res) => {
  const { trackingNumber, customerId, paymentMethod } = req.body;
  const pkg = await Package.create({ trackingNumber, customerId, paymentMethod, status: "Received at Warehouse" });
  res.json(pkg);
});

// Admin update package status
app.patch("/api/admin/package/status", auth("admin"), async (req, res) => {
  const { trackingNumber, status, location } = req.body;
  const pkg = await Package.findOneAndUpdate({ trackingNumber }, { status }, { new: true });
  if (!pkg) return res.status(404).json({ message: "Package not found" });
  await Tracking.create({ trackingNumber, status, location });
  res.json({ message: "Status updated", pkg });
});

// Customer tracking
app.get("/api/track/:tracking", async (req, res) => {
  const pkg = await Package.findOne({ trackingNumber: req.params.tracking });
  if (!pkg) return res.status(404).json({ message: "Not found" });
  res.json(pkg);
});

app.get("/api/track/:tracking/history", async (req, res) => {
  const history = await Tracking.find({ trackingNumber: req.params.tracking });
  res.json(history);
});

// Seed admin
app.post("/api/seed-admin", async (req, res) => {
  const hashed = await bcrypt.hash("admin123", 10);
  const admin = await User.create({ name: "System Admin", email: "admin@blueport.com", password: hashed, role: "admin" });
  res.json({ message: "Admin created", admin });
});

app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
