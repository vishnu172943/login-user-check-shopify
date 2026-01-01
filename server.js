//  require('dotenv').config();
// const express = require('express');
// const axios = require('axios');
// const cors = require('cors');
// const { rateLimit, ipKeyGenerator } = require('express-rate-limit');

// const app = express();

// // 1. Allow your Shopify Store to talk to this server
// app.use(cors({
//     origin: '*' // In production, change '*' to 'https://tumi-australia-uat.myshopify.com'
// }));

// // Use JSON parser for both API and Webhooks
// app.use(express.json());
// app.set('trust proxy', 1);

// // ---------------------------------------------------------
// //  EXISTING CONFIGURATION
// // ---------------------------------------------------------
// const SHOP_URL = process.env.SHOPIFY_STORE_URL; // e.g. tumi-australia-uat.myshopify.com
// const ACCESS_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;

// // Rate Limiter for the "Check User" endpoint
// const limiter = rateLimit({
//     windowMs: 30 * 60 * 1000, // 30 minutes
//     max: 9, // Block after 9 requests
//     message: { error: "Too many attempts for this email. Please wait." },
//     keyGenerator: (req) => {
//         return ipKeyGenerator(req) + "_" + (req.body.email || '');
//     }
// });

// // ---------------------------------------------------------
// //  ROUTE 1: CHECK EMAIL (Your existing logic)
// // ---------------------------------------------------------
// app.post('/api/check-user', limiter, async (req, res) => {
//     const { email } = req.body;

//     if (!email) {
//         return res.status(400).json({ error: "Email is required" });
//     }

//     try {
//         console.log(`Checking email: ${email}...`);

//         const shopUrl = `https://${SHOP_URL}/admin/api/2024-01/customers/search.json?query=email:${email}`;
        
//         const response = await axios.get(shopUrl, {
//             headers: {
//                 'X-Shopify-Access-Token': ACCESS_TOKEN,
//                 'Content-Type': 'application/json'
//             }
//         });

//         const userExists = response.data.customers.length > 0;

//         return res.json({ 
//             exists: userExists,
//             message: userExists ? "User found" : "User not found"
//         });

//     } catch (error) {
//         console.error("Shopify API Error:", error.response?.data || error.message);
//         return res.status(500).json({ error: "Internal Server Error" });
//     }
// });

// // ---------------------------------------------------------
// //  ROUTE 2: WEBHOOK LISTENER (The New Fixer)
// //  Triggers when a new customer is created in Shopify
// // ---------------------------------------------------------
//  // ---------------------------------------------------------
// //  ROUTE 2: WEBHOOK LISTENER (Updates Phone AND Marketing)
// // ---------------------------------------------------------
//  // ---------------------------------------------------------
// //  ROUTE 2: WEBHOOK LISTENER (Updates Phone AND Marketing)
// // ---------------------------------------------------------
//   // ---------------------------------------------------------
// //  ROUTE 2: WEBHOOK LISTENER (Save DOB Exactly As Is)
// // ---------------------------------------------------------
//  // ---------------------------------------------------------
// //  ROUTE 2: WEBHOOK LISTENER (Robust Line-by-Line Check)
// // ---------------------------------------------------------
// app.post('/api/webhooks/customer-create', async (req, res) => {
//     // 1. Acknowledge Shopify immediately
//     res.status(200).send('Webhook received');

//     const customer = req.body;
//     const customerId = customer.id;
//     const rawNote = customer.note || "";

//     console.log(`\n🔍 PROCESSING CUSTOMER: ${customerId}`);
//     console.log(`📄 RAW NOTE:\n${rawNote}`); 

//     // --- VARIABLES TO STORE DATA ---
//     let phoneNumber = null;
//     let shouldSubscribe = false;
//     let dobValue = null;

//     // --- STEP 1: LINE-BY-LINE EXTRACTION (Safer) ---
//     const noteLines = rawNote.split('\n');
    
//     // We will build a "clean" note by keeping lines we don't recognize
//     const cleanLines = [];

//     noteLines.forEach(line => {
//         const text = line.trim();
//         const lowerText = text.toLowerCase();

//         // 1. Check for PHONE
//         if (lowerText.startsWith('phone:')) {
//             // Remove "Phone:" and keep the rest
//             phoneNumber = text.substring(6).trim(); 
//         } 
//         // 2. Check for MARKETING
//         else if (lowerText.startsWith('marketing:')) {
//             const val = text.substring(10).trim().toLowerCase();
//             shouldSubscribe = (val === 'yes' || val === 'true');
//         } 
//         // 3. Check for DATE OF BIRTH (or DOB)
//         else if (lowerText.startsWith('date of birth:') || lowerText.startsWith('dob:')) {
//             // Find where the colon is and take everything after it
//             const separatorIndex = text.indexOf(':');
//             if (separatorIndex !== -1) {
//                 dobValue = text.substring(separatorIndex + 1).trim();
//             }
//         } 
//         // 4. Keep other lines (like "Title: Mr")
//         else {
//             if (text.length > 0) cleanLines.push(text);
//         }
//     });

//     const cleanNote = cleanLines.join('\n');

//     console.log(`📊 EXTRACTED DATA:`);
//     console.log(`   > Phone: ${phoneNumber}`);
//     console.log(`   > Marketing: ${shouldSubscribe}`);
//     console.log(`   > DOB: ${dobValue}`);  // <--- Check this in your logs!

//     // --- STEP 2: UPDATE SHOPIFY ---
//     if (phoneNumber || shouldSubscribe || dobValue || cleanNote !== rawNote) {
        
//         const updatePayload = {
//             customer: {
//                 id: customerId,
//                 note: cleanNote
//             }
//         };

//         if (phoneNumber) updatePayload.customer.phone = phoneNumber;

//         if (shouldSubscribe) {
//             updatePayload.customer.email_marketing_consent = {
//                 state: "subscribed",
//                 opt_in_level: "single_opt_in",
//                 consent_updated_at: new Date().toISOString()
//             };
//         }

//         // --- METAFIELD UPDATE ---
//         if (dobValue) {
//             updatePayload.customer.metafields = [
//                 {
//                     namespace: "custom",
//                     key: "date_of_birth",      // MUST MATCH EXACTLY in Shopify Admin
//                     value: dobValue,              // Sends "1/3/2003"
//                     type: "single_line_text_field" // MUST BE 'Single line text' in Shopify Admin
//                 }
//             ];
//         }

//         try {
//             await axios.put(`https://${SHOP_URL}/admin/api/2024-01/customers/${customerId}.json`, updatePayload, {
//                 headers: {
//                     'X-Shopify-Access-Token': ACCESS_TOKEN,
//                     'Content-Type': 'application/json'
//                 }
//             });
//             console.log(`✅ Success! Updated Shopify.`);
//         } catch (error) {
//             console.error("❌ Update Failed:", error.response ? JSON.stringify(error.response.data) : error.message);
//         }
//     } else {
//         console.log("⚠️ No actionable data found in note. Skipping update.");
//     }

// app.get('/auth/google', (req, res) => {
//     const authorizeUrl = googleClient.generateAuthUrl({
//         access_type: 'offline',
//         scope: ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'],
//         prompt: 'select_account'
//     });
//     res.redirect(authorizeUrl);
// });

// // ROUTE 4: GOOGLE CALLBACK
// app.get('/auth/google/callback', async (req, res) => {
//     // NOTE: This redirects the user back to your SHOPIFY STORE front-end
//     const redirectBase = `https://${SHOP_URL}`; 
    
//     try {
//         const { code } = req.query;
//         if (!code) return res.redirect(`${redirectBase}/?error=auth_cancelled`);

//         const { tokens } = await googleClient.getToken(code);
//         googleClient.setCredentials(tokens);
        
//         const ticket = await googleClient.verifyIdToken({
//             idToken: tokens.id_token,
//             audience: GOOGLE_CLIENT_ID
//         });
//         const payload = ticket.getPayload();
//         const { email, given_name: firstName, family_name: lastName } = payload;

//         // Check Existence
//         const existingCustomer = await findCustomerByEmail(email);

//         if (existingCustomer) {
//             // LOGIN EXISTING USER (Only if they have "social-user" tag)
//             const tags = Array.isArray(existingCustomer.tags) ? existingCustomer.tags : existingCustomer.tags.split(',').map(t => t.trim());
            
//             if (tags.includes('social-user')) {
//                 const tempPassword = generateSecurePassword();
//                 await updateCustomerPassword(existingCustomer.id, tempPassword);
//                 const token = createSimpleToken(email, tempPassword);
//                 // Redirect to Home with Token
//                 return res.redirect(`${redirectBase}/?token=${token}`);
//             } else {
//                 return res.redirect(`${redirectBase}/?error=manual_login_required`);
//             }
//         } else {
//             // NEW USER -> REDIRECT TO REGISTRATION FORM
//             const sig = generateSignature(email);
//             const params = new URLSearchParams({
//                 action: 'social_register', // Frontend listens for this
//                 email: email,
//                 fname: firstName || '',
//                 lname: lastName || '',
//                 sig: sig
//             });
//             return res.redirect(`${redirectBase}/?${params.toString()}`);
//         }

//     } catch (error) {
//         console.error("Auth Error:", error.message);
//         res.redirect(`${redirectBase}/?error=system_error`);
//     }
// });

// // ROUTE 5: COMPLETE SOCIAL SIGNUP
// app.post('/api/complete-social-signup', async (req, res) => {
//     try {
//         const { email, firstName, lastName, phone, dob, title, marketing, sig } = req.body;

//         // Security Check
//         if (sig !== generateSignature(email)) {
//             return res.status(403).json({ error: 'Security verification failed.' });
//         }

//         const existing = await findCustomerByEmail(email);
//         if (existing) return res.status(400).json({ error: 'Account already exists.' });

//         const password = generateSecurePassword();
//         const marketingConsent = marketing === true || marketing === 'on';
        
//         // Prepare Note (Matches Webhook Logic)
//         const noteString = `Title: ${title}\nDate of Birth: ${dob}\nPhone: ${phone}\nMarketing: ${marketingConsent ? "Yes" : "No"}`;

//         // Create Customer
//         await axios.post(`https://${SHOP_URL}/admin/api/2024-01/customers.json`, {
//             customer: {
//                 first_name: firstName,
//                 last_name: lastName,
//                 email: email,
//                 phone: phone, 
//                 password: password,
//                 password_confirmation: password,
//                 tags: "social-user",
//                 note: noteString,
//                 verified_email: true,
//                 send_email_welcome: false,
//                 accepts_marketing: marketingConsent
//             }
//         }, {
//             headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN, 'Content-Type': 'application/json' }
//         });

//         const token = createSimpleToken(email, password);
//         res.json({ success: true, token: token });

//     } catch (error) {
//         console.error("Signup Error:", error.response?.data || error.message);
//         const errMsg = error.response?.data?.errors ? JSON.stringify(error.response.data.errors) : 'Creation failed';
//         res.status(400).json({ error: errMsg });
//     }
// });
// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
// --- NEW IMPORTS FOR SOCIAL LOGIN ---
const { OAuth2Client } = require('google-auth-library');
const crypto = require('crypto');

const app = express();

// =====================================================
// 1. CONFIGURATION
// =====================================================
const SHOP_URL = process.env.SHOPIFY_STORE_URL; // e.g. tumi-australia-uat.myshopify.com
const ACCESS_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const CALLBACK_URL = process.env.CALLBACK_URL;
const STOREFRONT_ACCESS_TOKEN = process.env.SHOPIFY_STOREFRONT_TOKEN; // NEW: Needed to verify login
const PASSWORD_SECRET = process.env.PASSWORD_ROTATION_SECRET; // NEW: The secret key for daily passwords

// Initialize Google Client
const googleClient = new OAuth2Client(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    CALLBACK_URL
);

// 2. MIDDLEWARE
app.use(cors({ origin: '*' })); 
app.use(express.json());
app.set('trust proxy', 1);

// Rate Limiter
const limiter = rateLimit({
    windowMs: 30 * 60 * 1000, 
    max: 9, 
    message: { error: "Too many attempts. Please wait." },
    keyGenerator: (req) => ipKeyGenerator(req) + "_" + (req.body.email || '')
});

// =====================================================
// 3. HELPER FUNCTIONS (CRITICAL FOR SOCIAL LOGIN)
// =====================================================

// Generate secure password
function generateSecurePassword() {
    return crypto.randomBytes(12).toString('hex') + "A1!";
}

// Generate Security Signature (HMAC)
function generateSignature(email) {
    return crypto
        .createHmac('sha256', GOOGLE_CLIENT_SECRET)
        .update(email)
        .digest('hex');
}

// Create simple token
function createSimpleToken(email, password) {
    const data = JSON.stringify({ email, password });
    return Buffer.from(data).toString('base64');
}

// Find Customer by Email (GraphQL)
async function findCustomerByEmail(email) {
    const query = `
        query getCustomer($query: String!) {
            customers(first: 1, query: $query) {
                edges {
                    node {
                        id
                        email
                        firstName
                        lastName
                        tags
                    }
                }
            }
        }
    `;
    try {
        const response = await axios.post(`https://${SHOP_URL}/admin/api/2024-01/graphql.json`, {
            query,
            variables: { query: `email:${email}` }
        }, {
            headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN, 'Content-Type': 'application/json' }
        });
        const customers = response.data.data?.customers?.edges || [];
        return customers.length > 0 ? customers[0].node : null;
    } catch (error) {
        console.error("GraphQL Error:", error.message);
        return null;
    }
}
// 1. DETERMINISTIC PASSWORD GENERATOR (The Fix)
function getDailyPassword(email) {
    // Get today's date in UTC (e.g. "2024-01-02") so it's the same on every device
    const dateStr = new Date().toISOString().split('T')[0]; 
      console.log("you got daily password bro")
    // Create a hash using your Secret + Email + Date
    // This creates the SAME password for the SAME user for the SAME day
    const hash = crypto
        .createHmac('sha256', PASSWORD_SECRET)
        .update(email + dateStr)
        .digest('hex')
        .substring(0, 16);

    return `A1!${hash}`; // Add 'A1!' to meet Shopify's strength requirements
}

// 2. CHECK LOGIN STATUS (The Optimization)
async function checkShopifyLogin(email, password) {
    const loginMutation = `
        mutation customerAccessTokenCreate($input: CustomerAccessTokenCreateInput!) {
          customerAccessTokenCreate(input: $input) {
            customerAccessToken { accessToken }
          }
        }
    `;

    try {
        const response = await axios.post(`https://${SHOP_URL}/api/2025-10/graphql.json`, {
            query: loginMutation,
            variables: { input: { email, password } }
        }, {
            headers: { 
                'Content-Type': 'application/json',
                // Use Storefront Token (Read-Only) not Admin Token
                'X-Shopify-Storefront-Access-Token': STOREFRONT_ACCESS_TOKEN
            }
        });
        
        // If we get a token back, the password is valid
        return !!response.data?.data?.customerAccessTokenCreate?.customerAccessToken;
    } catch (e) {
        return false;
    }
}

// Update Customer Password (REST)
async function updateCustomerPassword(customerId, newPassword) {
    const numericId = customerId.includes('/') ? customerId.split('/').pop() : customerId;
    await axios.put(`https://${SHOP_URL}/admin/api/2024-01/customers/${numericId}.json`, {
        customer: {
            id: numericId,
            password: newPassword,
            password_confirmation: newPassword
        }
    }, {
        headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN, 'Content-Type': 'application/json' }
    });
}

// =====================================================
// 4. ROUTES
// =====================================================

// ROUTE 1: CHECK EMAIL
// app.post('/api/check-user', limiter, async (req, res) => {
//     const { email } = req.body;
//     if (!email) return res.status(400).json({ error: "Email is required" });

//     try {
//         console.log(`Checking email: ${email}...`);
//         const user = await findCustomerByEmail(email); // Re-using helper!
//         const userExists = !!user;

//         return res.json({ 
//             exists: userExists,
//             message: userExists ? "User found" : "User not found"
//         });
//     } catch (error) {
//         console.error("Shopify API Error:", error.message);
//         return res.status(500).json({ error: "Internal Server Error" });
//     }
// });
// =====================================================
// ROUTE 1: CHECK EMAIL (UPDATED FOR SOCIAL TAG)
// =====================================================
app.post('/api/check-user', limiter, async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    try {
        console.log(`Checking email: ${email}...`);
        const user = await findCustomerByEmail(email);
        const userExists = !!user;
        let isSocial = false;

        // CHECK TAGS IF USER EXISTS
        if (userExists && user.tags) {
            // Normalize tags (Handle if it comes as Array or String)
            const tags = Array.isArray(user.tags) 
                ? user.tags 
                : user.tags.split(',').map(t => t.trim());

            if (tags.includes('social-user')) {
                isSocial = true;
            }
        }

        return res.json({ 
            exists: userExists,
            isSocial: isSocial, // <--- New Flag sent to Frontend
            message: userExists ? "User found" : "User not found"
        });

    } catch (error) {
        console.error("Shopify API Error:", error.message);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});

// ROUTE 2: WEBHOOK LISTENER
app.post('/api/webhooks/customer-create', async (req, res) => {
    res.status(200).send('Webhook received');
    const customer = req.body;
    const customerId = customer.id;
    const rawNote = customer.note || "";

    console.log(`🔍 Processing Customer ${customerId}`);

    let phoneNumber = null;
    let shouldSubscribe = false;
    let dobValue = null;

    const noteLines = rawNote.split('\n');
    const cleanLines = [];

    noteLines.forEach(line => {
        const text = line.trim();
        const lowerText = text.toLowerCase();

        if (lowerText.startsWith('phone:')) {
            phoneNumber = text.substring(6).trim(); 
        } else if (lowerText.startsWith('marketing:')) {
            const val = text.substring(10).trim().toLowerCase();
            shouldSubscribe = (val === 'yes' || val === 'true');
        } else if (lowerText.startsWith('date of birth:') || lowerText.startsWith('dob:')) {
            const separatorIndex = text.indexOf(':');
            if (separatorIndex !== -1) dobValue = text.substring(separatorIndex + 1).trim();
        } else {
            if (text.length > 0) cleanLines.push(text);
        }
    });

    const cleanNote = cleanLines.join('\n');

    if (phoneNumber || shouldSubscribe || dobValue || cleanNote !== rawNote) {
        const updatePayload = { customer: { id: customerId, note: cleanNote } };
        if (phoneNumber) updatePayload.customer.phone = phoneNumber;
        if (shouldSubscribe) {
            updatePayload.customer.email_marketing_consent = {
                state: "subscribed",
                opt_in_level: "single_opt_in",
                consent_updated_at: new Date().toISOString()
            };
        }
        if (dobValue) {
            updatePayload.customer.metafields = [{
                namespace: "custom",
                key: "date_of_birth", 
                value: dobValue,
                type: "single_line_text_field"
            }];
        }

        try {
            await axios.put(`https://${SHOP_URL}/admin/api/2024-01/customers/${customerId}.json`, updatePayload, {
                headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN, 'Content-Type': 'application/json' }
            });
            console.log(`✅ Success! Customer updated.`);
        } catch (error) {
            console.error("❌ Update Failed:", error.response?.data || error.message);
        }
    }
});

// ROUTE 3: START GOOGLE OAUTH
app.get('/auth/google', (req, res) => {
    const authorizeUrl = googleClient.generateAuthUrl({
        access_type: 'offline',
        scope: ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'],
        prompt: 'select_account'
    });
    res.redirect(authorizeUrl);
});

// ROUTE 4: GOOGLE CALLBACK
app.get('/auth/google/callback', async (req, res) => {
    const redirectBase = `https://${SHOP_URL}`; 
    
    try {
        const { code } = req.query;
        if (!code) return res.redirect(`${redirectBase}/?error=auth_cancelled`);

        const { tokens } = await googleClient.getToken(code);
        googleClient.setCredentials(tokens);
        
        const ticket = await googleClient.verifyIdToken({
            idToken: tokens.id_token,
            audience: GOOGLE_CLIENT_ID
        });
        const payload = ticket.getPayload();
        const { email, given_name: firstName, family_name: lastName } = payload;

        const existingCustomer = await findCustomerByEmail(email);

        if (existingCustomer) {
            // LOGIN EXISTING
            const tags = Array.isArray(existingCustomer.tags) ? existingCustomer.tags : existingCustomer.tags.split(',').map(t => t.trim());
            if (tags.includes('social-user')) {
                // const tempPassword = generateSecurePassword();
                // await updateCustomerPassword(existingCustomer.id, tempPassword);
                // const token = createSimpleToken(email, tempPassword);
                // return res.redirect(`${redirectBase}/?token=${token}`);
                    // NEW CODE
// 1. Calculate what the password *should* be for today
              const dailyPassword = getDailyPassword(email);

// 2. Check if Shopify already has this password active
// This prevents the "Ping-Pong" effect. If valid, we SKIP the update.
             const isValid = await checkShopifyLogin(email, dailyPassword);

            if (isValid) {
                  console.log(`✅ Session Valid for ${email}. Skipping write.`);
             } else {
              console.log(`🔄 New Day or Stale Password. Updating password for ${email}...`);
    // 3. Only update if it's a new day (or first login of the day)
                await updateCustomerPassword(existingCustomer.id, dailyPassword);
              }

// 4. Return the token for Ghost Login
const token = createSimpleToken(email, dailyPassword);
return res.redirect(`${redirectBase}/?token=${token}`);
            } else {
                // return res.redirect(`${redirectBase}/?error=manual_login_required`);
                    const errorScript = `
                  <script>
                    window.opener.postMessage({ 
                      error: 'manual_login', 
                      message: 'Your social email is already used for register a TUMI account. Please sign in with your email address and password (right panel) to continue.' 
                    }, '*');
                    window.close();
                  </script>
                `;
                return res.send(errorScript);
            }
        } else {
            // REGISTER NEW
            const sig = generateSignature(email);
            const params = new URLSearchParams({
                action: 'social_register',
                email: email,
                fname: firstName || '',
                lname: lastName || '',
                sig: sig
            });
            return res.redirect(`${redirectBase}/?${params.toString()}`);
        }

    } catch (error) {
        console.error("Auth Error:", error.message);
        res.redirect(`${redirectBase}/?error=system_error`);
    }
});

// ROUTE 5: COMPLETE SIGNUP
app.post('/api/complete-social-signup', async (req, res) => {
    try {
        const { email, firstName, lastName, phone, dob, title, marketing, sig } = req.body;

        if (sig !== generateSignature(email)) {
            return res.status(403).json({ error: 'Security verification failed.' });
        }

        const existing = await findCustomerByEmail(email);
        if (existing) return res.status(400).json({ error: 'Account already exists.' });

        const password = getDailyPassword(email);
        const marketingConsent = marketing === true || marketing === 'on';
        const noteString = `Title: ${title}\nDate of Birth: ${dob}\nPhone: ${phone}\nMarketing: ${marketingConsent ? "Yes" : "No"}`;

        await axios.post(`https://${SHOP_URL}/admin/api/2024-01/customers.json`, {
            customer: {
                first_name: firstName,
                last_name: lastName,
                email: email,
                phone: phone, 
                password: password,
                password_confirmation: password,
                tags: "social-user",
                note: noteString,
                verified_email: true,
                send_email_welcome: false,
                accepts_marketing: marketingConsent
            }
        }, {
            headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN, 'Content-Type': 'application/json' }
        });

        const token = createSimpleToken(email, password);
        res.json({ success: true, token: token });

    } catch (error) {
        console.error("Signup Error:", error.response?.data || error.message);
        const errMsg = error.response?.data?.errors ? JSON.stringify(error.response.data.errors) : 'Creation failed';
        res.status(400).json({ error: errMsg });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
