const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = 'PINKWIN_SUPER_SECRET_KEY_2026';

// 1. Connect MongoDB
mongoose.connect('mongodb+srv://nishankazi514_db_user:37WxaTJIcjVHPBha@cluster0.df0jhsk.mongodb.net/pinkwin?retryWrites=true&w=majority')
  .then(() => console.log('MongoDB Connected Successfully'))
  .catch(err => console.log('MongoDB Connection Error:', err));

// Health Check Route
app.get('/', (req, res) => {
  res.send('Server is running & MongoDB connected!');
});

// 2. Database Models
const UserSchema = new mongoose.Schema({
    phoneNumber: { type: String, unique: true, sparse: true },
    email: { type: String, unique: true, sparse: true },
    password: { type: String, required: true },
    inviteCode: { type: String },
    balance: { type: Number, default: 0 },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['deposit', 'withdraw'], required: true },
    gateway: { type: String, required: true },
    amount: { type: Number, required: true },
    trxId: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});
const Transaction = mongoose.model('Transaction', TransactionSchema);

// 3. Auth Middleware
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Access Denied: No Token' });

    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ message: 'Invalid Token' });
    }
};

// 4. API Endpoints
app.post('/api/auth/register', async (req, res) => {
    try {
        const { phoneNumber, email, password, inviteCode } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            phoneNumber: phoneNumber || null,
            email: email || null,
            password: hashedPassword,
            inviteCode: inviteCode || ''
        });

        await newUser.save();
        res.status(201).json({ message: 'Registration Successful!' });
    } catch (error) {
        res.status(500).json({ message: 'Registration failed', error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        const user = await User.findOne({
            $or: [{ phoneNumber: identifier }, { email: identifier }]
        });
        if (!user) return res.status(400).json({ message: 'User not found' });

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ message: 'Invalid Password' });

        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: user._id, balance: user.balance, role: user.role } });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/wallet/deposit', authenticateToken, async (req, res) => {
    try {
        const { gateway, amount, trxId } = req.body;
        const newDeposit = new Transaction({ userId: req.user.id, type: 'deposit', gateway, amount, trxId });
        await newDeposit.save();
        res.json({ message: 'Deposit request submitted!' });
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
});

// 5. Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
