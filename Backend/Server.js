import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error(err));

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
    expiresAt: Date
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
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ msg: "All fields required" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ msg: "User already exists" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await OTP.deleteMany({ email });
    await OTP.create({
        email,
        otp,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000) // 10 min
    });

    await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Your OTP Code",
        text: `Your OTP is ${otp}. Valid for 10 minutes.`
    });

    res.json({ msg: "OTP sent to email" });
});

// Verify OTP & Register User
app.post("/register", async (req, res) => {
    const { name, email, password, otp } = req.body;
    const otpData = await OTP.findOne({ email, otp });

    if (!otpData) return res.status(400).json({ msg: "Invalid OTP" });
    if (otpData.expiresAt < new Date()) return res.status(400).json({ msg: "OTP expired" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hashedPassword });

    await OTP.deleteMany({ email });
    res.json({ msg: "User registered successfully" });
});

// Login User
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid password" });

    res.json({ msg: "Login successful", user });
});

app.listen(5000, () => console.log("🚀 Server running on port 5000"));
