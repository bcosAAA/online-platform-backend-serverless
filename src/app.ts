import { Hono } from 'hono';
import { cors } from 'hono/cors';
import authRoutes from './routes/auth.js'; 

// Define the environment variables interface
export interface Env {
  SUPABASE_URL: string; // Supabase project URL
  SUPABASE_ANON_KEY: string; // Supabase anonymous key
  JWT_SECRET: string; // Secret key for JWT signing
  GOOGLE_OAUTH_CLIENT_ID: string; // Google OAuth client ID
  GOOGLE_OAUTH_CLIENT_SECRET: string; // Google OAuth client secret
  SENDGRID_API_KEY: string; // SendGrid API key for sending emails
  SENDGRID_FROM_EMAIL: string; // Sender email address for SendGrid
}

// Create a new Hono app with environment bindings
const app = new Hono<{ Bindings: Env }>();

// Apply CORS middleware to all routes
app.use('*', cors({
  origin: 'http://localhost:5173', // Allow requests from this origin
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Use `allowMethods` instead of `methods`
}));

// Route all auth-related requests to the authRoutes handler
app.route('/api/auth', authRoutes); // Route for /api/auth
app.route('/auth', authRoutes); // Route for /auth

// Export the fetch handler for Cloudflare Workers
export default {
  async fetch(request: Request, env: Env) {
    // Pass the request and environment variables to the Hono app
    return app.fetch(request, env);
  }
};