 require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');

const app = express();

// 1. Allow your Shopify Store to talk to this server
app.use(cors({
    origin: '*' // In production, change '*' to 'https://tumi-australia-uat.myshopify.com'
}));

// Use JSON parser for both API and Webhooks
app.use(express.json());
app.set('trust proxy', 1);

// ---------------------------------------------------------
//  EXISTING CONFIGURATION
// ---------------------------------------------------------
const SHOP_URL = process.env.SHOPIFY_STORE_URL; // e.g. tumi-australia-uat.myshopify.com
const ACCESS_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;

// Rate Limiter for the "Check User" endpoint
const limiter = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 9, // Block after 9 requests
    message: { error: "Too many attempts for this email. Please wait." },
    keyGenerator: (req) => {
        return ipKeyGenerator(req) + "_" + (req.body.email || '');
    }
});

// ---------------------------------------------------------
//  ROUTE 1: CHECK EMAIL (Your existing logic)
// ---------------------------------------------------------
app.post('/api/check-user', limiter, async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: "Email is required" });
    }

    try {
        console.log(`Checking email: ${email}...`);

        const shopUrl = `https://${SHOP_URL}/admin/api/2024-01/customers/search.json?query=email:${email}`;
        
        const response = await axios.get(shopUrl, {
            headers: {
                'X-Shopify-Access-Token': ACCESS_TOKEN,
                'Content-Type': 'application/json'
            }
        });

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

// ---------------------------------------------------------
//  ROUTE 2: WEBHOOK LISTENER (The New Fixer)
//  Triggers when a new customer is created in Shopify
// ---------------------------------------------------------
app.post('/api/webhooks/customer-create', async (req, res) => {
    // 1. Respond to Shopify immediately (200 OK) to prevent timeouts
    res.status(200).send('Webhook received');

    const customer = req.body; // The customer object sent by Shopify
    const customerId = customer.id;
    const note = customer.note || "";

    console.log(`New Customer Created: ${customerId}. Checking for Phone in Note...`);

    // 2. Extract Phone from Note
    // Looking for pattern: "Phone: +614..."
    const phoneMatch = note.match(/Phone:\s*(\+?\d+)/i);

    if (phoneMatch && phoneMatch[1]) {
        const phoneNumber = phoneMatch[1]; // The extracted number

        console.log(`✅ Found phone ${phoneNumber} in note. Moving to official field...`);

        try {
            // 3. Update Customer via Admin API
            const updateUrl = `https://${SHOP_URL}/admin/api/2024-01/customers/${customerId}.json`;

            await axios.put(updateUrl, {
                customer: {
                    id: customerId,
                    phone: phoneNumber, // Save to official field
                    note: note.replace(phoneMatch[0], '').trim() // Optional: Remove the phone line from the note so it looks clean
                }
            }, {
                headers: {
                    'X-Shopify-Access-Token': ACCESS_TOKEN,
                    'Content-Type': 'application/json'
                }
            });

            console.log(`🎉 Success! Customer ${customerId} phone updated to ${phoneNumber}.`);

        } catch (error) {
            // Log full error details for debugging
            console.error("❌ Failed to update phone number:", error.response ? JSON.stringify(error.response.data) : error.message);
        }
    } else {
        console.log("ℹ️ No phone number found in notes. Skipping update.");
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
