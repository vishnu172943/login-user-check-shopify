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
  // ---------------------------------------------------------
//  ROUTE 2: WEBHOOK LISTENER (Save DOB Exactly As Is)
// ---------------------------------------------------------
 // ---------------------------------------------------------
//  ROUTE 2: WEBHOOK LISTENER (Robust Line-by-Line Check)
// ---------------------------------------------------------
app.post('/api/webhooks/customer-create', async (req, res) => {
    // 1. Acknowledge Shopify immediately
    res.status(200).send('Webhook received');

    const customer = req.body;
    const customerId = customer.id;
    const rawNote = customer.note || "";

    console.log(`\n🔍 PROCESSING CUSTOMER: ${customerId}`);
    console.log(`📄 RAW NOTE:\n${rawNote}`); 

    // --- VARIABLES TO STORE DATA ---
    let phoneNumber = null;
    let shouldSubscribe = false;
    let dobValue = null;

    // --- STEP 1: LINE-BY-LINE EXTRACTION (Safer) ---
    const noteLines = rawNote.split('\n');
    
    // We will build a "clean" note by keeping lines we don't recognize
    const cleanLines = [];

    noteLines.forEach(line => {
        const text = line.trim();
        const lowerText = text.toLowerCase();

        // 1. Check for PHONE
        if (lowerText.startsWith('phone:')) {
            // Remove "Phone:" and keep the rest
            phoneNumber = text.substring(6).trim(); 
        } 
        // 2. Check for MARKETING
        else if (lowerText.startsWith('marketing:')) {
            const val = text.substring(10).trim().toLowerCase();
            shouldSubscribe = (val === 'yes' || val === 'true');
        } 
        // 3. Check for DATE OF BIRTH (or DOB)
        else if (lowerText.startsWith('date of birth:') || lowerText.startsWith('dob:')) {
            // Find where the colon is and take everything after it
            const separatorIndex = text.indexOf(':');
            if (separatorIndex !== -1) {
                dobValue = text.substring(separatorIndex + 1).trim();
            }
        } 
        // 4. Keep other lines (like "Title: Mr")
        else {
            if (text.length > 0) cleanLines.push(text);
        }
    });

    const cleanNote = cleanLines.join('\n');

    console.log(`📊 EXTRACTED DATA:`);
    console.log(`   > Phone: ${phoneNumber}`);
    console.log(`   > Marketing: ${shouldSubscribe}`);
    console.log(`   > DOB: ${dobValue}`);  // <--- Check this in your logs!

    // --- STEP 2: UPDATE SHOPIFY ---
    if (phoneNumber || shouldSubscribe || dobValue || cleanNote !== rawNote) {
        
        const updatePayload = {
            customer: {
                id: customerId,
                note: cleanNote
            }
        };

        if (phoneNumber) updatePayload.customer.phone = phoneNumber;

        if (shouldSubscribe) {
            updatePayload.customer.email_marketing_consent = {
                state: "subscribed",
                opt_in_level: "single_opt_in",
                consent_updated_at: new Date().toISOString()
            };
        }

        // --- METAFIELD UPDATE ---
        if (dobValue) {
            updatePayload.customer.metafields = [
                {
                    namespace: "custom",
                    key: "date_of_birth",      // MUST MATCH EXACTLY in Shopify Admin
                    value: dobValue,              // Sends "1/3/2003"
                    type: "single_line_text_field" // MUST BE 'Single line text' in Shopify Admin
                }
            ];
        }

        try {
            await axios.put(`https://${SHOP_URL}/admin/api/2024-01/customers/${customerId}.json`, updatePayload, {
                headers: {
                    'X-Shopify-Access-Token': ACCESS_TOKEN,
                    'Content-Type': 'application/json'
                }
            });
            console.log(`✅ Success! Updated Shopify.`);
        } catch (error) {
            console.error("❌ Update Failed:", error.response ? JSON.stringify(error.response.data) : error.message);
        }
    } else {
        console.log("⚠️ No actionable data found in note. Skipping update.");
    }
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
