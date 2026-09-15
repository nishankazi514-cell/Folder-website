const express = require('express');
const path = require('path');
const app = express();

const PORT = process.env.PORT || 10000;

// Body parser middleware (JSON ডেটা গ্রহণ করার জন্য)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ১. স্ট্যাটিক ফাইল সার্ভ করা (Root Directory থেকে)
app.use(express.static(__dirname));

// ২. রেজিস্ট্রেশন API Route (যা ফ্রন্টএন্ড কল করছে)
app.post('/api/v1/auth/register', (req, res) => {
    const { accountIdentifier, password, referralCode } = req.body;

    console.log("New User Data Received:", { accountIdentifier, referralCode });

    // সফল রেসপন্স রিটার্ন
    return res.status(200).json({
        success: true,
        message: "রেজিস্ট্রেশন সফল হয়েছে!"
    });
});

// ৩. হোম পেজ বা মূল রুট
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// সার্ভার লিসেনিং
app.listen(PORT, () => {
    console.log(`BDXbet Engine running on Port ${PORT}`);
});
