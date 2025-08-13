import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Health check endpoint (required for Railway)
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK' });
});

// MongoDB connection with improved error handling
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("✅ MongoDB Connected"))
.catch(err => {
  console.error("❌ MongoDB Connection Error:", err);
  process.exit(1); // Exit if DB connection fails
});

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String
});
const User = mongoose.model("User", userSchema);

// OTP Schema
const otpSchema = new mongoose.Schema({
  email: String,
  otp: String,
  expiresAt: {
    type: Date,
    default: Date.now,
    expires: 600 // 10 minutes
  }
});
const OTP = mongoose.model("OTP", otpSchema);

// Nodemailer Transport
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Send OTP
app.post("/send-otp", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ msg: "All fields required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ msg: "User already exists" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Remove existing OTPs and create new one
    await OTP.deleteMany({ email });
    await OTP.create({ email, otp });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP is ${otp}. Valid for 10 minutes.`
    });

    res.json({ msg: "OTP sent to email" });
  } catch (error) {
    console.error("Send OTP Error:", error);
    res.status(500).json({ msg: "Server error" });
  }
});

// Verify OTP & Register User
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, otp } = req.body;
    const otpData = await OTP.findOne({ email, otp });

    if (!otpData) {
      return res.status(400).json({ msg: "Invalid OTP" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hashedPassword });

    await OTP.deleteMany({ email });
    res.json({ msg: "User registered successfully" });
  } catch (error) {
    console.error("Registration Error:", error);
    res.status(500).json({ msg: "Server error" });
  }
});

// Login User
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(400).json({ msg: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid password" });
    }

    res.json({ msg: "Login successful", user });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ msg: "Server error" });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ msg: "Something broke!" });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
});