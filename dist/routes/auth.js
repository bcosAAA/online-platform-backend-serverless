// src/routes/auth.ts
import express from 'express';
import supabase from '../config/supabase.js'; // Use .js for moduleResolution: node16/nodenext
import bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import { OAuth2Client } from 'google-auth-library';
// Create a nodemailer transporter
const resetTokens = new Map();
const router = express.Router();
// Configure nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});
const client = new OAuth2Client({
    clientId: process.env.GOOGLE_OAUTH_CLIENT_ID,
    clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
    redirectUri: process.env.GOOGLE_REDIRECT_URI,
});
// Email template function
const generateEmail = (verificationCode) => `
  <!DOCTYPE html>
  <html>
  <head>
    <style>
      body { margin: 0; font-family: Arial, sans-serif; background: #f9f9f9; color: #333; }
      .email-container { max-width: 500px; margin: 40px auto; background: #ffffff; border: 1px solid #eaeaea; border-radius: 8px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1); overflow: hidden; }
      .email-header { background: #253B74; padding: 20px; text-align: center; color: white; }
      .email-body { padding: 30px; text-align: center; }
      .email-body h2 { color: #91BE3F; }
      .verification-code { font-size: 32px; font-weight: bold; color: #253B74; background: #f5f5f5; border: 1px solid #ddd; border-radius: 8px; padding: 15px 30px; margin: 20px auto; display: inline-block; }
      .note { font-size: 14px; color: #666; margin-top: 20px; }
      .email-footer { background: #f5f5f5; padding: 15px; text-align: center; font-size: 12px; color: #777; }
    </style>
  </head>
  <body>
    <div class="email-container">
      <div class="email-header">
        <h1>BCOS</h1>
      </div>
      <div class="email-body">
        <h2>تفعيل إعادة تعيين كلمة المرور</h2>
        <p>مرحباً،</p>
        <p>لقد طلبت إعادة تعيين كلمة المرور. يرجى استخدام الرمز أدناه للمتابعة:</p>
        <div class="verification-code">${verificationCode}</div>
        <p class="note">هذا الرمز سينتهي خلال 15 دقيقة. إذا لم تطلب هذا، يرجى تجاهل هذه الرسالة.</p>
        <p>شكراً لك،<br>فريق BCOS</p>
      </div>
      <div class="email-footer">
        &copy; ${new Date().getFullYear()} BCOS. جميع الحقوق محفوظة.
      </div>
    </div>
  </body>
  </html>
`;
// Register a new user
router.post('/register', async (req, res) => {
    const { fullName, email, password, phoneNumber, profession, termsAccepted, newsletterSubscription } = req.body;
    console.log('Register request received:', { email, fullName });
    try {
        // Hash the password before storing it
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log('Password hashed successfully');
        // Insert the new user and return the inserted row
        const { data, error } = await supabase
            .from('users')
            .insert([
            {
                full_name: fullName,
                email,
                password: hashedPassword,
                phone_number: phoneNumber,
                profession,
                terms_accepted: termsAccepted,
                newsletter_subscription: newsletterSubscription,
            },
        ])
            .select('*'); // Return the inserted row
        if (error) {
            console.error('Error inserting user:', error.message);
            res.status(400).json({ error: error.message });
            return; // Ensure the function exits after sending the response
        }
        // Check if data is returned
        if (!data || data.length === 0) {
            console.error('No data returned after user insertion');
            res.status(500).json({ error: 'Failed to retrieve inserted user' });
            return;
        }
        console.log('User registered successfully:', data[0]);
        res.status(201).json({ message: 'User registered successfully', data: data[0] });
    }
    catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
// Login a user
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    console.log('Login request received:', { email });
    try {
        // Find the user by email
        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email);
        if (error) {
            console.error('Error finding user:', error.message);
            res.status(400).json({ error: error.message });
            return; // Ensure the function exits after sending the response
        }
        // Check if no user was found
        if (!users || users.length === 0) {
            console.error('User not found:', email);
            res.status(404).json({ error: 'User not found' });
            return; // Ensure the function exits after sending the response
        }
        // Get the first (and only) user
        const user = users[0];
        console.log('User found:', user.email);
        // Compare the provided password with the hashed password in the database
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            console.error('Invalid password for user:', email);
            res.status(401).json({ error: 'Invalid password' });
            return; // Ensure the function exits after sending the response
        }
        console.log('Login successful for user:', email);
        res.status(200).json({ message: 'Login successful', user });
    }
    catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
// Request password reset
router.post('/reset-password/request', async (req, res) => {
    const { email } = req.body;
    console.log('Password reset request received:', { email });
    try {
        // Check if the user exists in the database
        const { data: users, error: supabaseError } = await supabase
            .from('users')
            .select('*')
            .eq('email', email);
        if (supabaseError) {
            console.error('Supabase error:', supabaseError);
            return res.status(500).json({ error: 'Database error' });
        }
        if (!users?.length) {
            console.error('User not found for password reset:', email);
            return res.status(404).json({ error: 'User not found' });
        }
        // Generate a reset token and code
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
        resetTokens.set(resetToken, { email, code: resetCode, timestamp: Date.now() });
        console.log('Reset token and code generated:', { resetToken, resetCode });
        // Send the reset code via email using the HTML template
        await transporter.sendMail({
            to: email,
            subject: 'Password Reset Verification',
            html: generateEmail(resetCode), // Use the HTML template here
        });
        console.log('Reset code email sent to:', email);
        res.json({ token: resetToken });
    }
    catch (error) {
        console.error('Error during password reset request:', error);
        res.status(500).json({ error: 'Server error' });
    }
});
// Verify reset code
router.post('/reset-password/verify', async (req, res) => {
    const { token, code } = req.body;
    console.log('Reset code verification request received:', { token, code });
    if (!token || !code) {
        console.error('Token or code is missing:', { token, code });
        return res.status(400).json({ error: 'Token and code are required' });
    }
    const resetData = resetTokens.get(token);
    if (!resetData || Date.now() - resetData.timestamp > 3600000) {
        console.error('Invalid or expired token:', token);
        resetTokens.delete(token);
        return res.status(400).json({ error: 'Invalid or expired token' });
    }
    if (resetData.code !== code) {
        console.error('Invalid reset code:', code);
        return res.status(400).json({ error: 'Invalid code' });
    }
    console.log('Reset code verified successfully:', { token });
    res.json({ valid: true });
});
// Reset password
router.post('/reset-password/request', async (req, res) => {
    const { email } = req.body;
    console.log('Password reset request received:', { email });
    try {
        // Check if the user exists in the database
        const { data: users, error: supabaseError } = await supabase
            .from('users')
            .select('*')
            .eq('email', email);
        if (supabaseError) {
            console.error('Supabase error:', supabaseError);
            return res.status(500).json({ error: 'Database error' });
        }
        if (!users?.length) {
            console.error('User not found for password reset:', email);
            return res.status(404).json({ error: 'User not found' });
        }
        // Generate a reset token and code
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
        resetTokens.set(resetToken, { email, code: resetCode, timestamp: Date.now() });
        console.log('Reset token and code generated:', { resetToken, resetCode });
        // Send the reset code via email using the HTML template
        await transporter.sendMail({
            to: email,
            subject: 'Password Reset Verification',
            html: generateEmail(resetCode), // Use the HTML template here
        });
        console.log('Reset code email sent to:', email);
        res.json({ token: resetToken }); // Ensure the token is sent in the response
    }
    catch (error) {
        console.error('Error during password reset request:', error);
        res.status(500).json({ error: 'Server error' });
    }
});
router.post('/google', async (req, res) => {
    const { credential } = req.body;
    if (!credential) {
        return res.status(400).json({ error: 'No credential provided' });
    }
    try {
        const ticket = await client.verifyIdToken({
            idToken: credential,
            audience: process.env.GOOGLE_OAUTH_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        if (!payload) {
            throw new Error('Failed to get payload from Google token');
        }
        const { email, name, picture } = payload;
        // Check if user exists
        let { data: user, error: fetchError } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();
        if (fetchError && fetchError.code !== 'PGRST116') {
            throw new Error('Database error checking existing user');
        }
        if (!user) {
            // Create new user
            const hashedPassword = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 10);
            const { data: newUser, error: insertError } = await supabase
                .from('users')
                .insert({
                email,
                full_name: name,
                password: hashedPassword,
                profile_picture: picture,
                auth_provider: 'google',
                terms_accepted: true,
            })
                .select()
                .single();
            if (insertError) {
                console.error('Insert error:', insertError);
                throw new Error('Failed to create user');
            }
            user = newUser;
        }
        else {
            // Update existing user's Google info if they were originally email users
            if (user.auth_provider === 'email') {
                const { error: updateError } = await supabase
                    .from('users')
                    .update({
                    profile_picture: picture,
                    auth_provider: 'google',
                })
                    .eq('id', user.id);
                if (updateError) {
                    console.error('Error updating user:', updateError);
                    // Continue anyway as this is not critical
                }
            }
        }
        if (!user) {
            throw new Error('Failed to retrieve user data');
        }
        res.status(200).json({
            message: 'Google authentication successful',
            user: {
                id: user.id,
                email: user.email,
                fullName: user.full_name,
                profilePicture: user.profile_picture,
                authProvider: user.auth_provider
            },
        });
    }
    catch (error) {
        console.error('Google authentication error:', error);
        res.status(401).json({
            error: 'Google authentication failed',
            details: error instanceof Error ? error.message : 'Unknown error'
        });
    }
});
export default router;
