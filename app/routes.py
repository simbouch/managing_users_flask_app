from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db, bcrypt
from app.models import User

# Route to add a new user (admin only)
@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('list_users'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if the email already exists in the database
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please use a different email.', 'danger')
            return redirect(url_for('add_user'))

        # Hash the password before storing it
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create a new user and add to the database
        new_user = User(username=username, email=email, password=hashed_password, role='user')
        db.session.add(new_user)
        db.session.commit()

        flash('User successfully added!', 'success')
        return redirect(url_for('list_users'))

    return render_template('add_user.html')

# Route to update a user
@app.route('/update_user/<int:id>', methods=['GET', 'POST'])
@login_required
def update_user(id):
    user = User.query.get_or_404(id)

    # Only admins or the user themselves can update the account
    if current_user.role != 'admin' and current_user.id != user.id:
        flash('Access denied. You can only update your own account.', 'danger')
        return redirect(url_for('list_users'))

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        if request.form['password']:
            user.password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('list_users'))

    return render_template('update_user.html', user=user)

# Route to list all users
@app.route('/list_users')
@login_required
def list_users():
    users = User.query.all()
    return render_template('list_users.html', users=users)

# Route to delete a user (admin only)
@app.route('/delete_user/<int:id>', methods=['POST'])
@login_required
def delete_user(id):
    if current_user.role != 'admin':
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('list_users'))

    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} deleted successfully.', 'success')
    return redirect(url_for('list_users'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if there are any users in the database
    user_count = User.query.count()
    if user_count == 0:
        flash('No users exist yet. Please add the first user.', 'info')
        return redirect(url_for('add_first_user'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Find user by email
        user = User.query.filter_by(email=email).first()

        # Check if the user exists
        if not user:
            flash('User does not exist. Please check the email.', 'danger')
            return render_template('login.html')

        # Check if password matches
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('list_users'))
        else:
            flash('Login failed. Check your email and password.', 'danger')

    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Route to add the first user (admin)
@app.route('/add_first_user', methods=['GET', 'POST'])
def add_first_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Hash the password before storing it
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create the first user as admin
        new_user = User(username=username, email=email, password=hashed_password, role='admin')
        db.session.add(new_user)
        db.session.commit()

        flash('Admin user created successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('add_first_user.html')

# Define a route for the homepage that redirects to the list of users
@app.route('/')
@login_required
def home():
    return redirect(url_for('list_users'))
