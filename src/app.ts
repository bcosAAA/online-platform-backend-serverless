import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { serve } from '@hono/node-server'; // Import the serve function
import authRoutes from './routes/auth.js';

interface Env {
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
  JWT_SECRET: string;
  GOOGLE_OAUTH_CLIENT_ID: string;
  GOOGLE_OAUTH_CLIENT_SECRET: string;
  SENDGRID_API_KEY: string;
  SENDGRID_FROM_EMAIL: string;
}

const app = new Hono<{ Bindings: Env }>();

// Parse the PORT environment variable as a number
const port = parseInt(process.env.PORT || '5000', 10);

// Enable CORS for all routes
app.use('*', cors());

// Route for authentication
app.route('/auth', authRoutes);
app.route('/api/auth', authRoutes);

// Start the server
try {
  serve({
    fetch: app.fetch,
    port, // Now `port` is guaranteed to be a number
  }, () => {
    console.log(`Server running on http://localhost:${port}`);
  });
} catch (error) {
  console.error('Failed to start server:', error);
}

// Export for compatibility with Cloudflare Workers or other environments
export default {
  fetch: app.fetch,
};