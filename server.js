require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

// 1. Allow your Shopify Store to talk to this server
app.use(cors({
    origin: '*' // In production, change '*' to 'https://your-store.com'
}));

app.use(express.json());
app.set('trust proxy', 1)
// 2. Security: Limit checks to 5 per minute per IP address
 // 2. Security: Limit strictly by IP + Email combination
const limiter = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minute
    max: 9, // Block after 9 requests
    message: { error: "Too many attempts for this email. Please wait." },
    // This function tells the limiter to track "IP + Email" instead of just IP
    keyGenerator: (req) => {
        // If no email is provided, fall back to just IP to be safe
        return req.ip + "_" + (req.body.email || '');
    }
});

// 3. The API Route
app.post('/api/check-user', limiter, async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: "Email is required" });
    }

    try {
        console.log(`Checking email: ${email}...`);

        // Shopify Admin API: Search for customer by email
        const shopUrl = `https://${process.env.SHOPIFY_STORE_URL}/admin/api/2024-01/customers/search.json?query=email:${email}`;
        
        const response = await axios.get(shopUrl, {
            headers: {
                'X-Shopify-Access-Token': process.env.SHOPIFY_ADMIN_TOKEN,
                'Content-Type': 'application/json'
            }
        });

        // If the 'customers' array is not empty, the user exists
        const userExists = response.data.customers.length > 0;

        return res.json({ 
            exists: userExists,
            message: userExists ? "User found" : "User not found"
        });

    } catch (error) {
        console.error("Shopify API Error:", error.response?.data || error.message);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
