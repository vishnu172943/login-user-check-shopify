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
// function generateSecurePassword() {
//     return crypto.randomBytes(12).toString('hex') + "A1!";
// }

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
// function getDailyPassword(email) {
//     // Get today's date in UTC (e.g. "2024-01-02") so it's the same on every device
//     // const dateStr = new Date().toISOString().split('T')[0]; 
//       console.log("you got daily password bro")
//     // Create a hash using your Secret + Email + Date
//     // This creates the SAME password for the SAME user for the SAME day
//     const hash = crypto
//         .createHmac('sha256', PASSWORD_SECRET)
//         .update(email)
//         .digest('hex')
//         .substring(0, 16);

//     return `A1!${hash}`; // Add 'A1!' to meet Shopify's strength requirements
// }
function getSocialPassword(email) {
    // 1. Safety Check: Normalize the email so 'User@Test.com' matches 'user@test.com'
    const normalizedEmail = email.toLowerCase().trim();

    // 2. Generate Hash: Only depends on Email + Secret
    const hash = crypto
        .createHmac('sha256', PASSWORD_SECRET)
        .update(normalizedEmail) 
        .digest('hex')
        .substring(0, 16);

    return `A1!${hash}`; 
}

// 2. CHECK LOGIN STATUS (The Optimization)
// async function checkShopifyLogin(email, password) {
//     const loginMutation = `
//         mutation customerAccessTokenCreate($input: CustomerAccessTokenCreateInput!) {
//           customerAccessTokenCreate(input: $input) {
//             customerAccessToken { accessToken }
//           }
//         }
//     `;

//     try {
//         const response = await axios.post(`https://${SHOP_URL}/api/2025-10/graphql.json`, {
//             query: loginMutation,
//             variables: { input: { email, password } }
//         }, {
//             headers: { 
//                 'Content-Type': 'application/json',
//                 // Use Storefront Token (Read-Only) not Admin Token
//                 'X-Shopify-Storefront-Access-Token': STOREFRONT_ACCESS_TOKEN
//             }
//         });
        
//         // If we get a token back, the password is valid
//         return !!response.data?.data?.customerAccessTokenCreate?.customerAccessToken;
//     } catch (e) {
//         return false;
//     }
// }
 async function checkShopifyLogin(email, password) {
    const loginMutation = `
        mutation customerAccessTokenCreate($input: CustomerAccessTokenCreateInput!) {
          customerAccessTokenCreate(input: $input) {
            customerAccessToken { accessToken }
            customerUserErrors { message }
          }
        }
    `;

    try {
        console.log("🔍 Testing Password for:", email); // DEBUG LOG 1
        
        const response = await axios.post(`https://${SHOP_URL}/api/2025-10/graphql.json`, {
            query: loginMutation,
            variables: { input: { email, password } }
        }, {
            headers: { 
                'Content-Type': 'application/json',
                'X-Shopify-Storefront-Access-Token': STOREFRONT_ACCESS_TOKEN 
            }
        });
        
        // DEBUG LOG 2: Check what Shopify actually said
        const data = response.data?.data?.customerAccessTokenCreate;
        console.log("🔍 Shopify Reply:", JSON.stringify(data));

        if (data?.customerUserErrors?.length > 0) {
            console.log("❌ Shopify User Error:", data.customerUserErrors[0].message);
        }

        return !!data?.customerAccessToken;
    } catch (e) {
        // DEBUG LOG 3: Check Network/System Errors
        console.error("❌ API Call Failed:", e.message);
        if (e.response) {
             console.error("❌ Response Data:", JSON.stringify(e.response.data));
        }
        return false;
    }
}
// Update Customer Password (REST)
async function updateCustomerPassword(customerId, newPassword) {
        console.log("updating password")
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
              const socialPassword = getSocialPassword(email);

// 2. Check if Shopify already has this password active
// This prevents the "Ping-Pong" effect. If valid, we SKIP the update.
             const isValid = await checkShopifyLogin(email, socialPassword);

            if (isValid) {
                  console.log(`✅ Session Valid for ${email}. Skipping write.`);
             } else {
              console.log(`🔄 New Day or Stale Password. Updating password for ${email}...`);
    // 3. Only update if it's a new day (or first login of the day)
                await updateCustomerPassword(existingCustomer.id,socialPassword);
              }

// 4. Return the token for Ghost Login
const token = createSimpleToken(email, socialPassword);
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

        const password = getSocialPassword(email);
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
