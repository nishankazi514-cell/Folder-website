require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();

// Security Headers
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());

// CORS Setup
const allowedOrigin = process.env.ALLOWED_ORIGIN || '*';
app.use(cors({ origin: allowedOrigin, optionsSuccessStatus: 200 }));

// Static Files
app.use(express.static(path.join(__dirname, 'public')));

// Rate Limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 150,
    message: { success: false, message: "অতিরিক্ত রিকোয়েস্ট পাঠানো হয়েছে।" }
});
app.use('/api/', apiLimiter);

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'BDXBET_SUPER_SECRET_KEY';

// Standard working URI or fallback
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/bdxbet_db";

// Schemas
const UserSchema = new mongoose.Schema({
    phoneOrEmail: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    referralCode: { type: String, default: null },
    balance: { type: Number, default: 0.00 },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    createdAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    gateway: { type: String, required: true },
    amount: { type: Number, required: true },
    trxId: { type: String, required: true, unique: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);

// JWT Middleware
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: "টোকেন অনুপস্থিত।" });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ success: false, message: "অকার্যকর টোকেন।" });
        req.user = decoded;
        next();
    });
};

// Routes
app.post('/api/v1/auth/register', async (req, res) => {
    try {
        const { phoneOrEmail, password, referralCode } = req.body;
        if(!phoneOrEmail || !password) return res.status(400).json({ success: false, message: "তথ্য অসম্পূর্ণ।" });
        
        const existingUser = await User.findOne({ phoneOrEmail });
        if (existingUser) return res.status(400).json({ success: false, message: "ব্যবহারকারী পূর্বেই বিদ্যমান।" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ phoneOrEmail, password: hashedPassword, referralCode });

        await newUser.save();
        res.status(201).json({ success: true, message: "অ্যাকাউন্ট তৈরি সফল হয়েছে।" });
    } catch (err) {
        res.status(500).json({ success: false, message: "সার্ভার ত্রুটি!", error: err.message });
    }
});

app.post('/api/v1/auth/login', async (req, res) => {
    try {
        const { phoneOrEmail, password } = req.body;
        const user = await User.findOne({ phoneOrEmail });
        if (!user) return res.status(400).json({ success: false, message: "ব্যবহারকারী পাওয়া যায়নি।" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "ভুল পাসওয়ার্ড।" });

        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
        res.status(200).json({
            success: true,
            token,
            user: { id: user._id, phoneOrEmail: user.phoneOrEmail, balance: user.balance, role: user.role }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "লগইন ব্যর্থ হয়েছে।" });
    }
});

app.get('/api/v1/user/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.status(200).json({ success: true, user });
    } catch (err) {
        res.status(500).json({ success: false, message: "ডাটা লোড করতে ব্যর্থ।" });
    }
});

app.post('/api/v1/wallet/deposit', verifyToken, async (req, res) => {
    try {
        const { gateway, amount, trxId } = req.body;
        if (!amount || Number(amount) <= 0 || !trxId) return res.status(400).json({ success: false, message: "সঠিক তথ্য দিন।" });

        const existingTrx = await Transaction.findOne({ trxId: trxId.trim() });
        if(existingTrx) return res.status(400).json({ success: false, message: "এই TrxID ব্যবহৃত হয়েছে।" });

        const newTrx = new Transaction({ userId: req.user.id, gateway, amount: Number(amount), trxId: trxId.trim() });
        await newTrx.save();
        res.status(200).json({ success: true, message: "ডিপোজিট আবেদন গৃহীত হয়েছে।" });
    } catch (err) {
        res.status(500).json({ success: false, message: "প্রসেসিং ব্যর্থ।" });
    }
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Express App Immediately, then connect DB
app.listen(PORT, () => {
    console.log(`BDXbet Engine running on Port ${PORT}`);
    mongoose.connect(MONGO_URI)
        .then(() => console.log("MongoDB Connected Successfully"))
        .catch(err => console.error("Database connection warning (Server running regardless):", err.message));
});
    
