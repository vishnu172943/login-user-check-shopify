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
 // ---------------------------------------------------------
//  ROUTE 2: WEBHOOK LISTENER (Updates Phone AND Marketing)
// ---------------------------------------------------------
 // ---------------------------------------------------------
//  ROUTE 2: WEBHOOK LISTENER (Updates Phone AND Marketing)
// ---------------------------------------------------------
app.post('/api/webhooks/customer-create', async (req, res) => {
    // 1. Acknowledge Shopify immediately
    res.status(200).send('Webhook received');

    const customer = req.body;
    const customerId = customer.id;
    const rawNote = customer.note || "";

    console.log(`🔍 Processing Customer ${customerId}`);

    // 2. Extract Data using robust matching
    // Matches "Phone: +61..." or "Phone: 04..." even with dashes/spaces
    const phoneMatch = rawNote.match(/Phone:\s*([+\d\-\(\)\s]+)/i);
    const phoneNumber = phoneMatch ? phoneMatch[1].trim() : null;

    const marketingMatch = rawNote.match(/Marketing:\s*(Yes|No)/i);
    const shouldSubscribe = marketingMatch && marketingMatch[1].toLowerCase() === 'yes';

    // 3. CLEANUP LOGIC (The Fix)
    // We split the note line-by-line and remove the ones we processed
    const noteLines = rawNote.split('\n');
    const cleanNote = noteLines.filter(line => {
        const text = line.trim().toLowerCase();
        // Remove line if it starts with "phone:" or "marketing:"
        return !text.startsWith('phone:') && !text.startsWith('marketing:');
    }).join('\n').trim();

    // 4. Update if we found data OR if we need to clean the note
    if (phoneNumber || shouldSubscribe || cleanNote !== rawNote) {
        console.log(`🚀 Updating... Phone: ${phoneNumber}, Marketing: ${shouldSubscribe}`);

        const updatePayload = {
            customer: {
                id: customerId,
                note: cleanNote // Send the cleaned note back
            }
        };

        if (phoneNumber) {
            updatePayload.customer.phone = phoneNumber;
        }

        if (shouldSubscribe) {
            updatePayload.customer.email_marketing_consent = {
                state: "subscribed",
                opt_in_level: "single_opt_in",
                consent_updated_at: new Date().toISOString()
            };
        }

        try {
            await axios.put(`https://${SHOP_URL}/admin/api/2024-01/customers/${customerId}.json`, updatePayload, {
                headers: {
                    'X-Shopify-Access-Token': ACCESS_TOKEN,
                    'Content-Type': 'application/json'
                }
            });
            console.log(`✅ Success! Note cleaned and profile updated.`);
        } catch (error) {
            console.error("❌ Update Failed:", error.response ? JSON.stringify(error.response.data) : error.message);
        }
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
