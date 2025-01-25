import { Hono, Context } from 'hono'; // Import Context from Hono
import { cors } from 'hono/cors';
import { createClient } from '@supabase/supabase-js';
import { OAuth2Client } from 'google-auth-library';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import sgMail from '@sendgrid/mail'; // Import SendGrid

export interface Env {
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
  JWT_SECRET: string;
  GOOGLE_OAUTH_CLIENT_ID: string;
  GOOGLE_OAUTH_CLIENT_SECRET: string;
  SENDGRID_API_KEY: string; // SendGrid API key
  SENDGRID_FROM_EMAIL: string; // Sender email address
}

// Define a custom User type
type User = {
  id: string;
  email: string;
};

// Define a custom Variables type
type Variables = {
  user: User;
};

// Extend the Hono Context type with your custom Variables
type AppContext = Context<{
  Bindings: Env;
  Variables: Variables;
}>;

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// In-memory reset token storage (replace with KV in production)
const resetTokens = new Map();

// Configure Supabase and Google OAuth clients
const getSupabase = (env: Env) => createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY);
const getGoogleClient = (env: Env) => new OAuth2Client({
  clientId: env.GOOGLE_OAUTH_CLIENT_ID,
  clientSecret: env.GOOGLE_OAUTH_CLIENT_SECRET,
});

// Utility function to generate JWT
const generateToken = (user: User, secret: string) => 
  jwt.sign({ id: user.id, email: user.email }, secret, { expiresIn: '24h' });

// Utility function to send email using SendGrid
const sendEmail = async (env: Env, to: string, subject: string, text: string) => {
  sgMail.setApiKey(env.SENDGRID_API_KEY); // Set SendGrid API key

  const msg = {
    to, // Recipient email
    from: env.SENDGRID_FROM_EMAIL, // Sender email
    subject, // Email subject
    text, // Email body (plain text)
  };

  try {
    await sgMail.send(msg); // Send the email
    console.log('Email sent successfully');
  } catch (error) {
    console.error('Error sending email:', error);
    throw new Error('Failed to send email');
  }
};

// Register route
app.post('/register', async (c: AppContext) => {
  const { 
    fullName, 
    email, 
    password, 
    phoneNumber, 
    profession, 
    termsAccepted, 
    newsletterSubscription 
  } = await c.req.json();

  const supabase = getSupabase(c.env);

  try {
    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Insert the new user into the database
    const { data, error } = await supabase
      .from('users')
      .insert([{
        full_name: fullName,
        email,
        password: hashedPassword,
        phone_number: phoneNumber,
        profession,
        terms_accepted: termsAccepted,
        newsletter_subscription: newsletterSubscription,
      }])
      .select('*');

    if (error) return c.json({ error: error.message }, 400);
    if (!data || data.length === 0) return c.json({ error: 'Failed to retrieve inserted user' }, 500);

    return c.json({ 
      message: 'User registered successfully', 
      data: data[0] 
    }, 201);
  } catch (error) {
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Login route
app.post('/login', async (c: AppContext) => {
  const { email, password } = await c.req.json();
  const supabase = getSupabase(c.env);

  try {
    // Fetch the user from the database
    const { data: users, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email);

    if (error) return c.json({ error: error.message }, 400);
    if (!users || users.length === 0) return c.json({ error: 'User not found' }, 404);

    const user = users[0];
    // Compare the provided password with the hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) return c.json({ error: 'Invalid password' }, 401);

    // Generate a JWT for the authenticated user
    const token = generateToken(user, c.env.JWT_SECRET);

    return c.json({
      message: 'Login successful',
      user,
      token,
    });
  } catch (error) {
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Google OAuth login
app.post('/google', async (c: AppContext) => {
  const { credential } = await c.req.json();
  const supabase = getSupabase(c.env);
  const googleClient = getGoogleClient(c.env);

  try {
    // Verify the Google ID token
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: c.env.GOOGLE_OAUTH_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    if (!payload) throw new Error('Failed to get payload from Google token');

    const { email, name, picture } = payload;

    // Check if the user already exists in the database
    let { data: user, error: fetchError } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (fetchError && fetchError.code !== 'PGRST116') {
      throw new Error('Database error checking existing user');
    }

    // If the user doesn't exist, create a new user
    if (!user) {
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

      if (insertError) throw new Error('Failed to create user');
      user = newUser;
    }

    // Generate a JWT for the authenticated user
    const token = generateToken(user, c.env.JWT_SECRET);

    return c.json({
      message: 'Google authentication successful',
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        profilePicture: user.profile_picture,
        authProvider: user.auth_provider,
      },
      token,
    });
  } catch (error) {
    return c.json({ 
      error: 'Google authentication failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, 401);
  }
});

// Password reset request
app.post('/reset-password/request', async (c: AppContext) => {
  const { email } = await c.req.json();
  const supabase = getSupabase(c.env);

  try {
    // Check if the user exists in the database
    const { data: users, error: supabaseError } = await supabase
      .from('users')
      .select('*')
      .eq('email', email);

    if (supabaseError) return c.json({ error: 'Database error' }, 500);
    if (!users?.length) return c.json({ error: 'User not found' }, 404);

    // Generate a reset token and code
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    resetTokens.set(resetToken, { email, code: resetCode, timestamp: Date.now() });

    // Send the reset code via email
    const emailSubject = 'Password Reset Request';
    const emailText = `Your password reset code is: ${resetCode}`;
    await sendEmail(c.env, email, emailSubject, emailText);

    return c.json({ token: resetToken });
  } catch (error) {
    return c.json({ error: 'Server error' }, 500);
  }
});

// Middleware to authenticate routes
const authenticateToken = async (c: AppContext, next: () => Promise<void>) => {
  const authHeader = c.req.header('Authorization');
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return c.json({ error: 'No token provided' }, 401);

  try {
    // Verify the JWT and set the user in the context
    const user = jwt.verify(token, c.env.JWT_SECRET) as User;
    c.set('user', user);
    await next();
  } catch (error) {
    return c.json({ error: 'Invalid or expired token' }, 403);
  }
};

// Get user details
app.get('/me', authenticateToken, async (c: AppContext) => {
  const supabase = getSupabase(c.env);
  const user = c.get('user'); // Get the authenticated user from the context

  try {
    // Fetch the user details from the database
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', user.id)
      .single();

    if (error) return c.json({ error: 'User not found' }, 404);

    // Remove the password from the response
    const { password, ...userWithoutPassword } = data;

    return c.json({ user: userWithoutPassword });
  } catch (error) {
    return c.json({ error: 'Internal server error' }, 500);
  }
});

export default app;