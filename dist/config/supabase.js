// src/config/supabase.ts
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
// Load environment variables from .env file
dotenv.config();
// Get Supabase credentials from environment variables
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
// Throw an error if Supabase credentials are missing
if (!supabaseUrl || !supabaseKey) {
    throw new Error('Missing Supabase credentials');
}
// Create and export the Supabase client
const supabase = createClient(supabaseUrl, supabaseKey);
export default supabase;
