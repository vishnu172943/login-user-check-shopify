 require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');
const crypto = require('crypto');

const app = express();

/* * CONFIGURATION & MIDDLEWARE
 * Sets up environment variables, Google Client, and Express middleware.
 * Rate limiting is applied to prevent brute-force attacks on check/login endpoints.
 */
const SHOP_URL = process.env.SHOPIFY_STORE_URL;
const ACCESS_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const CALLBACK_URL = process.env.CALLBACK_URL;
const STOREFRONT_ACCESS_TOKEN = process.env.SHOPIFY_STOREFRONT_TOKEN;
const PASSWORD_SECRET = process.env.PASSWORD_ROTATION_SECRET;

const googleClient = new OAuth2Client(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    CALLBACK_URL
);

app.use(cors({ origin: '*' })); 
app.use(express.json());
app.set('trust proxy', 1);

const limiter = rateLimit({
    windowMs: 30 * 60 * 1000, 
    max: 9, 
    message: { error: "Too many attempts. Please wait." },
    keyGenerator: (req) => ipKeyGenerator(req) + "_" + (req.body.email || '')
});

/* * HELPER: SIGNATURE GENERATOR
 * Creates a cryptographic HMAC signature based on the email. 
 * This is passed to the frontend and verified later to ensure the 'complete-signup' request 
 * actually came from a valid Google Auth success, preventing spoofing.
 */
function generateSignature(email) {
    return crypto
        .createHmac('sha256', GOOGLE_CLIENT_SECRET)
        .update(email)
        .digest('hex');
}

/* * HELPER: TOKEN GENERATOR
 * Encodes the email and password into a base64 string.
 * This allows the frontend to decode it and perform a "ghost login" (form submission) 
 * immediately after the social auth flow completes.
 */
function createSimpleToken(email, password) {
    const data = JSON.stringify({ email, password });
    return Buffer.from(data).toString('base64');
}

/* * HELPER: FIND CUSTOMER (ADMIN API)
 * Queries Shopify Admin GraphQL to check if a user exists.
 * We need the ID and Tags to determine if the user is a 'social-user' or a standard email user.
 */
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

/* * HELPER: DETERMINISTIC PASSWORD GENERATOR
 * Generates a secure password based on the Email + Server Secret.
 * This ensures that every time a specific Google user logs in, we generate the 
 * exact same password, allowing them to authenticate with Shopify without storing the password.
 */
function getSocialPassword(email) {
    const normalizedEmail = email.toLowerCase().trim();
    const hash = crypto
        .createHmac('sha256', PASSWORD_SECRET)
        .update(normalizedEmail) 
        .digest('hex')
        .substring(0, 16);

    return `A1!${hash}`; 
}

/* * HELPER: CHECK LOGIN (STOREFRONT API)
 * Optimization Step: Tries to log in using the generated social password via Storefront API.
 * If this succeeds, we know the password in Shopify is already correct, so we skip 
 * the Admin API write operation (saving API rate limits).
 */
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
        const response = await axios.post(`https://${SHOP_URL}/api/2025-10/graphql.json`, {
            query: loginMutation,
            variables: { input: { email, password } }
        }, {
            headers: { 
                'Content-Type': 'application/json',
                'X-Shopify-Storefront-Access-Token': STOREFRONT_ACCESS_TOKEN 
            }
        });
        
        const data = response.data?.data?.customerAccessTokenCreate;
        return !!data?.customerAccessToken;
    } catch (e) {
        return false;
    }
}

/* * HELPER: UPDATE PASSWORD (ADMIN API)
 * Uses the Admin REST API to force-update a customer's password.
 * This is called if 'checkShopifyLogin' fails, ensuring the user's Shopify account 
 * matches the deterministic social password.
 */
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

/* * ENDPOINT: CHECK USER STATUS
 * Called by frontend to determine if it should show the Login or Register UI.
 * Returns 'isSocial' so the frontend knows if it should force a Google login 
 * or allow standard password entry.
 */
app.post('/api/check-user', limiter, async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    try {
        const user = await findCustomerByEmail(email);
        const userExists = !!user;
        let isSocial = false;

        if (userExists && user.tags) {
            const tags = Array.isArray(user.tags) 
                ? user.tags 
                : user.tags.split(',').map(t => t.trim());

            if (tags.includes('social-user')) {
                isSocial = true;
            }
        }

        return res.json({ 
            exists: userExists,
            isSocial: isSocial, 
            message: userExists ? "User found" : "User not found"
        });

    } catch (error) {
        return res.status(500).json({ error: "Internal Server Error" });
    }
});

/* * ENDPOINT: WEBHOOK LISTENER
 * Listens for 'customer/create' webhooks from Shopify.
 * Parses the customer 'note' field to extract data (Phone, DOB) that couldn't be 
 * handled by the standard registration form, and updates the customer record accordingly.
 */
app.post('/api/webhooks/customer-create', async (req, res) => {
    res.status(200).send('Webhook received');
    const customer = req.body;
    const customerId = customer.id;
    const rawNote = customer.note || "";

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
        } catch (error) {
            console.error("Update Failed:", error.response?.data || error.message);
        }
    }
});

/* * ENDPOINT: START GOOGLE OAUTH
 * Redirects the user to the Google Consent screen.
 */
app.get('/auth/google', (req, res) => {
    const authorizeUrl = googleClient.generateAuthUrl({
        access_type: 'offline',
        scope: ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'],
        prompt: 'select_account'
    });
    res.redirect(authorizeUrl);
});

/* * ENDPOINT: GOOGLE OAUTH CALLBACK
 * Handles the code returned from Google. 
 * 1. Verifies Google identity.
 * 2. Checks if user exists in Shopify.
 * 3. IF EXISTING SOCIAL: Syncs password if needed, returns login token.
 * 4. IF EXISTING MANUAL: Blocks login, tells user to use password form.
 * 5. IF NEW: Redirects to frontend to complete signup (phone/dob collection).
 */
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
            // EXISTING USER LOGIC
            const tags = Array.isArray(existingCustomer.tags) ? existingCustomer.tags : existingCustomer.tags.split(',').map(t => t.trim());
            if (tags.includes('social-user')) {
                // Determine what the password should be
                const socialPassword = getSocialPassword(email);

                // Check if that password currently works (Optimization)
                const isValid = await checkShopifyLogin(email, socialPassword);

                if (!isValid) {
                   // If stale, update it via Admin API
                    await updateCustomerPassword(existingCustomer.id, socialPassword);
                }

                // Generate login token and redirect
                const token = createSimpleToken(email, socialPassword);
                return res.redirect(`${redirectBase}/?token=${token}`);
            } else {
                // User has an account but it's NOT a social account. Block access.
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
            // NEW USER LOGIC
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

/* * ENDPOINT: COMPLETE SOCIAL SIGNUP
 * Finalizes the creation of a new social user.
 * Verifies the signature (security), creates the customer in Shopify with the 
 * deterministic password and 'social-user' tag, and returns the login token.
 */
app.post('/api/complete-social-signup', async (req, res) => {
    try {
        const { email, firstName, lastName, phone, dob, title, marketing, sig } = req.body;

        // Security Check: Ensure email wasn't tampered with
        if (sig !== generateSignature(email)) {
            return res.status(403).json({ error: 'Security verification failed.' });
        }

        const existing = await findCustomerByEmail(email);
        if (existing) return res.status(400).json({ error: 'Account already exists.' });

        const password = getSocialPassword(email);
        const marketingConsent = marketing === true || marketing === 'on';
        const noteString = `Title: ${title}\nDate of Birth: ${dob}\nPhone: ${phone}\nMarketing: ${marketingConsent ? "Yes" : "No"}`;

        // Create Customer in Shopify
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
