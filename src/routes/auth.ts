import { Hono, Context } from 'hono';
import { cors } from 'hono/cors';
import { createClient } from '@supabase/supabase-js';
import { OAuth2Client } from 'google-auth-library';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import sgMail from '@sendgrid/mail';
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

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
  Variables: Variables;
}>;

const app = new Hono<{ Variables: Variables }>();

// In-memory reset token storage (replace with KV in production)
const resetTokens = new Map();

// Configure Supabase and Google OAuth clients
const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!);
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_OAUTH_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET!,
});

// Utility function to generate JWT
const generateToken = (user: User) => 
  jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET!, { expiresIn: '24h' });

// Utility function to send email using SendGrid
const sendEmail = async (to: string, subject: string, text: string) => {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY!);

  const msg = {
    to,
    from: process.env.SENDGRID_FROM_EMAIL!,
    subject,
    text,
  };

  try {
    await sgMail.send(msg);
    console.log('Email sent successfully to:', to);
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

  console.log('Register request received for email:', email);

  try {
    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('Password hashed successfully');
    
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

    if (error) {
      console.error('Error inserting user:', error.message);
      return c.json({ error: error.message }, 400);
    }
    if (!data || data.length === 0) {
      console.error('Failed to retrieve inserted user');
      return c.json({ error: 'Failed to retrieve inserted user' }, 500);
    }

    console.log('User registered successfully:', data[0].email);
    return c.json({ 
      message: 'User registered successfully', 
      data: data[0] 
    }, 201);
  } catch (error) {
    console.error('Internal server error during registration:', error);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Login route
app.post('/login', async (c: AppContext) => {
  const { email, password } = await c.req.json();
  console.log('Login request received for email:', email);

  try {
    // Fetch the user from the database
    const { data: users, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email);

    if (error) {
      console.error('Error fetching user:', error.message);
      return c.json({ error: error.message }, 400);
    }
    if (!users || users.length === 0) {
      console.error('User not found:', email);
      return c.json({ error: 'User not found' }, 404);
    }

    const user = users[0];
    // Compare the provided password with the hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      console.error('Invalid password for user:', email);
      return c.json({ error: 'Invalid password' }, 401);
    }

    // Generate a JWT for the authenticated user
    const token = generateToken(user);
    console.log('Login successful for user:', email);

    return c.json({
      message: 'Login successful',
      user,
      token,
    });
  } catch (error) {
    console.error('Internal server error during login:', error);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Google OAuth login
app.post('/google', async (c: AppContext) => {
  const { credential } = await c.req.json();
  console.log('Google OAuth request received');

  try {
    // Verify the Google ID token
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_OAUTH_CLIENT_ID!,
    });

    const payload = ticket.getPayload();
    if (!payload) {
      console.error('Failed to get payload from Google token');
      throw new Error('Failed to get payload from Google token');
    }

    const { email, name, picture } = payload;
    console.log('Google OAuth payload received for email:', email);

    // Check if the user already exists in the database
    let { data: user, error: fetchError } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (fetchError && fetchError.code !== 'PGRST116') {
      console.error('Database error checking existing user:', fetchError.message);
      throw new Error('Database error checking existing user');
    }

    // If the user doesn't exist, create a new user
    if (!user) {
      console.log('Creating new user for email:', email);
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
        console.error('Failed to create user:', insertError.message);
        throw new Error('Failed to create user');
      }
      user = newUser;
    }

    // Generate a JWT for the authenticated user
    const token = generateToken(user);
    console.log('Google authentication successful for user:', email);

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
    console.error('Google authentication failed:', error);
    return c.json({ 
      error: 'Google authentication failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, 401);
  }
});

// Password reset request
app.post('/reset-password/request', async (c: AppContext) => {
  const { email } = await c.req.json();
  console.log('Password reset request received for email:', email);

  try {
    // Check if the user exists in the database
    const { data: users, error: supabaseError } = await supabase
      .from('users')
      .select('*')
      .eq('email', email);

    if (supabaseError) {
      console.error('Database error:', supabaseError.message);
      return c.json({ error: 'Database error' }, 500);
    }
    if (!users?.length) {
      console.error('User not found:', email);
      return c.json({ error: 'User not found' }, 404);
    }

    // Generate a reset token and code
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    resetTokens.set(resetToken, { email, code: resetCode, timestamp: Date.now() });
    console.log('Reset token generated for email:', email);

    // Send the reset code via email
    const emailSubject = 'Password Reset Request';
    const emailText = `Your password reset code is: ${resetCode}`;
    await sendEmail(email, emailSubject, emailText);

    return c.json({ token: resetToken });
  } catch (error) {
    console.error('Server error during password reset request:', error);
    return c.json({ error: 'Server error' }, 500);
  }
});

// Middleware to authenticate routes
const authenticateToken = async (c: AppContext, next: () => Promise<void>) => {
  const authHeader = c.req.header('Authorization');
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.error('No token provided');
    return c.json({ error: 'No token provided' }, 401);
  }

  try {
    // Verify the JWT and set the user in the context
    const user = jwt.verify(token, process.env.JWT_SECRET!) as User;
    c.set('user', user);
    console.log('User authenticated:', user.email);
    await next();
  } catch (error) {
    console.error('Invalid or expired token:', error);
    return c.json({ error: 'Invalid or expired token' }, 403);
  }
};

// Get user details
app.get('/me', authenticateToken, async (c: AppContext) => {
  const user = c.get('user'); // Get the authenticated user from the context
  console.log('Fetching user details for:', user.email);

  try {
    // Fetch the user details from the database
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', user.id)
      .single();

    if (error) {
      console.error('User not found:', error.message);
      return c.json({ error: 'User not found' }, 404);
    }

    // Remove the password from the response
    const { password, ...userWithoutPassword } = data;
    console.log('User details fetched successfully for:', user.email);

    return c.json({ user: userWithoutPassword });
  } catch (error) {
    console.error('Internal server error fetching user details:', error);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

export default app;