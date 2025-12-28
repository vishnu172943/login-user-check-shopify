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
app.post('/api/webhooks/customer-create', async (req, res) => {
    res.status(200).send('Webhook received');

    const customer = req.body;
    const customerId = customer.id;
    const note = customer.note || "";

    console.log(`🔍 Customer ${customerId} Created. Note: ${JSON.stringify(note)}`);

    // 1. Extract Phone
    const phoneMatch = note.match(/Phone:\s*(\+?\d+)/i);
    const phoneNumber = phoneMatch ? phoneMatch[1] : null;

    // 2. Extract Marketing Choice
    const marketingMatch = note.match(/Marketing:\s*(Yes|No)/i);
    const shouldSubscribe = marketingMatch && marketingMatch[1].toLowerCase() === 'yes';

    if (phoneNumber || shouldSubscribe) {
        console.log(`🚀 Updating Customer ${customerId}... Phone: ${phoneNumber}, Marketing: ${shouldSubscribe}`);

        try {
            // Prepare the update payload
            const updatePayload = {
                customer: {
                    id: customerId,
                    // Clean up the note (remove the Phone/Marketing lines so they don't look messy)
                    note: note.replace(/Phone:.*(\n|$)/i, '').replace(/Marketing:.*(\n|$)/i, '').trim()
                }
            };

            // Add Phone if found
            if (phoneNumber) {
                updatePayload.customer.phone = phoneNumber;
            }

            // Add Marketing Consent if "Yes"
            if (shouldSubscribe) {
                updatePayload.customer.email_marketing_consent = {
                    state: "subscribed",
                    opt_in_level: "single_opt_in",
                    consent_updated_at: new Date().toISOString()
                };
            }

            // Send to Shopify
            await axios.put(`https://${SHOP_URL}/admin/api/2024-01/customers/${customerId}.json`, updatePayload, {
                headers: {
                    'X-Shopify-Access-Token': ACCESS_TOKEN,
                    'Content-Type': 'application/json'
                }
            });

            console.log(`✅ Customer ${customerId} updated successfully!`);

        } catch (error) {
            console.error("❌ Update Failed:", error.response ? JSON.stringify(error.response.data) : error.message);
        }
    } else {
        console.log("ℹ️ No Phone or Marketing updates needed.");
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
