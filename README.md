# Flask User Management App

This project is a **Flask** web app for user management with admin and regular user roles. Admins can add new users, while all users can view a list of registered users. Authentication is handled using **Flask-Login** with secure session management and password hashing via **Flask-Bcrypt**.

## Quick Setup

1. **Install dependencies**:

    pip install -r requirements.txt
   

2. **Set environment variables** in a `.env` file:
   
    SECRET_KEY=your-very-secure-random-key


3. **Run the app**:
 
    python run.py


4. **Access the app** at [http://127.0.0.1:5000](http://127.0.0.1:5000).

## Features
- Admin can add new users
- Role-based access control (admin & regular users)
- User authentication with session management
- SQLite database

This project is part of the **Simplon AI Developer Formation**.
