// src/schema.ts
import { Client } from 'pg';

// Function to create the `users` table
export const createUserTable = async () => {
  const client = new Client({
    connectionString: process.env.SUPABASE_URL, // Use your Supabase connection string
    ssl: { rejectUnauthorized: false }, // Required for Supabase
  });

  try {
    await client.connect();

    // Define the SQL query to create the `users` table
    const query = `
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  full_name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  phone_number TEXT,
  profession TEXT,
  terms_accepted BOOLEAN DEFAULT FALSE,
  newsletter_subscription BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW(),
  auth_provider VARCHAR(50) DEFAULT 'email',
  profile_picture TEXT -- Optional column for profile pictures
);
`;

    // Execute the query
    await client.query(query);
    console.log('Users table created successfully');
  } catch (error) {
    console.error('Error creating users table:', error);
  } finally {
    await client.end();
  }
};