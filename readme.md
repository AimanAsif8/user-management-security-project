# Node.js Login Page with MongoDB Integration and Admin User Management

## Overview
This project is a Node.js application designed to provide a secure login page with MongoDB integration for user authentication. Additionally, it includes features for user management by an admin user.

## Features
- **User Authentication**: Users can securely log in using their credentials.
- **MongoDB Integration**: Utilizes MongoDB to store user information securely.
- **Admin User Management**: Admin users have access to manage other user accounts.
- **Password Encryption**: User passwords are encrypted to ensure data security.
- **Session Management**: Sessions are managed to maintain user authentication across requests.

## Installation
1. Clone this repository to your local machine.
2. Install dependencies using `npm install`.
3. Set up MongoDB database and configure the connection string in `config.js`.
4. Run the application using `node app.js` or `npm start`.

## Usage
1. Visit the login page and enter your credentials.
2. Upon successful login, you will be redirected to the dashboard.
3. Admin users can access the admin panel to manage user accounts.
4. Regular users can view their profile and update their information.

## Configuration
- **MongoDB Configuration**: Update the MongoDB connection string and database details in `config.js`.
- **Admin User Creation**: Admin users can be created manually in the database or through a specific route designed for admin user creation.

## Dependencies
- **Express**: Node.js web application framework.
- **MongoDB**: NoSQL database for storing user information.
- **bcrypt**: Library for hashing and encrypting passwords.
- **express-session**: Middleware for managing sessions in Express.
- **dotenv**: Library for loading environment variables from a `.env` file.

## .env files needed
Create a `.env` file and add the following variables:

```dotenv
PORT=5000
MONGODB_CONNECTION_STRING='please enter your mongodb connection string'
ADMIN_USERNAME="add admin username"
ADMIN_PASSWORD="add admin password"



