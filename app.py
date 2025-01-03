from flask import Flask, render_template, request, redirect, url_for, session
from flask import flash
from flask import jsonify
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask import abort
from datetime import timedelta
import sqlite3
from validate_email import validate_email
import bcrypt
import random
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = "your_secure_secret_key"
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.permanent_session_lifetime = timedelta(minutes=30)
app.jinja_env.globals['csrf_token'] = lambda: csrf.generate_csrf()

csrf = CSRFProtect(app)
csrf.init_app(app)



DATABASE = r'D:\Third Yer Sem 1\Security 6005CEM\CourseWork2\webapp\JinxVapeShop.db'

# Define REGEXP function for SQLite
def regexp(expr, item):
    reg = re.compile(expr)
    return reg.search(item) is not None

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')  # Ensure foreign key enforcement
    conn.create_function("REGEXP", 2, regexp)  # Add REGEXP function
    return conn

# Utility functions
def is_valid_email(email):
    return validate_email(email)

def is_valid_password(password):
    return password.isdigit() and len(password) == 10

def get_user_id(email, cursor):
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    return user['id'] if user else None

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not is_valid_email(email):
            return render_template('register.html', error="Invalid email address. Please use a valid email.")
        if not is_valid_password(password):
            return render_template('register.html', error="Password must be 10 numeric digits.")

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password.decode('utf-8')))
            conn.commit()
            return render_template('register.html', success="Account created successfully! You can now log in.")
        except sqlite3.IntegrityError:
            return render_template('register.html', error="Email already registered.")
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']

        if not is_valid_email(email):
            return "Invalid email address. Please use a valid email."

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            otp = random.randint(100000, 999999)
            session['otp'] = otp
            session['user_email'] = email
            print(f"Generated OTP: {otp}")  # Simulate email for testing
            return redirect(url_for('otp_page'))
        elif user:
            return "Invalid password. Please try again."
        else:
            return "Email not registered. Please sign up."

    return render_template('login.html')

@app.route('/otp', methods=['GET', 'POST'])
def otp_page():
    if request.method == 'POST':
        user_otp = request.form['otp']
        if 'otp' in session and int(user_otp) == session['otp']:
            del session['otp']
            session['logged_in'] = True
            return redirect(url_for('homepage'))
        else:
            return "Invalid OTP. Please try again."
    return render_template('otp.html')
@app.route('/', methods=['GET', 'POST'])
def homepage():
    logged_in = 'user_email' in session  # Check if the user is logged in
    search_query = None
    search_results_message = None

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        # Retrieve and normalize search query
        search_query = request.form.get('query', '').strip().lower()

    if search_query:
        # Filter products based on normalized search query
        cursor.execute('''
            SELECT * FROM products WHERE LOWER(name) LIKE ?
        ''', (f"%{search_query}%",))
        products = cursor.fetchall()

        if len(products) == 1:
            # Redirect to the product page if only one product matches
            product_id = products[0]['id']
            conn.close()
            return redirect(url_for('product_page', product_id=product_id))
        elif len(products) == 0:
            # Show a message if no products match
            search_results_message = f"No products found for '{search_query}'."
    else:
        # Fetch all products if no search query
        cursor.execute('SELECT * FROM products')
        products = cursor.fetchall()

    # Fetch reviews for each product
    product_reviews = {}
    for product in products:
        cursor.execute('''
            SELECT reviews.review_text, reviews.rating, users.email
            FROM reviews
            JOIN users ON reviews.user_id = users.id
            WHERE reviews.product_id = ?
        ''', (product['id'],))
        product_reviews[product['id']] = cursor.fetchall()

    conn.close()

    return render_template(
        'homepage.html',
        products=products,
        product_reviews=product_reviews,
        logged_in=logged_in,
        search_results_message=search_results_message
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('homepage'))


@app.route('/search', methods=['POST'])
def search():
    try:
        query = request.form.get('query', '').strip()
        if not query:
            return redirect(url_for('homepage'))
        
        # Perform the search operation
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM products WHERE LOWER(name) LIKE ?', (f"%{query.lower()}%",))
        results = cursor.fetchall()
        conn.close()

        if not results:
            return redirect(url_for('homepage', message="No products found."))

        if len(results) == 1:
            # Redirect to product page if only one result
            return redirect(url_for('product_page', product_id=results[0]['id']))
        
        return render_template('search_results.html', results=results, query=query)

    except Exception as e:
        app.logger.error(f"Error during search: {e}")
        return jsonify({"error": "An unexpected error occurred during search."}), 500


@app.route('/product/<int:product_id>')
def product_page(product_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
    product = cursor.fetchone()
    conn.close()
    if product:
        return render_template('product.html', product=product)
    else:
        return "Product not found.", 404

@app.route('/add_to_basket/<int:product_id>', methods=['POST'])
def add_to_basket(product_id):
    if 'user_email' not in session:
        return redirect(url_for('login'))

    user_email = session['user_email']
    quantity = int(request.form.get('quantity', 1))
    conn = get_db_connection()
    cursor = conn.cursor()
    user_id = get_user_id(user_email, cursor)

    cursor.execute('SELECT * FROM basket WHERE user_id = ? AND product_id = ?', (user_id, product_id))
    basket_item = cursor.fetchone()

    if basket_item:
        cursor.execute('UPDATE basket SET quantity = quantity + ? WHERE user_id = ? AND product_id = ?', (quantity, user_id, product_id))
    else:
        cursor.execute('INSERT INTO basket (user_id, product_id, quantity) VALUES (?, ?, ?)', (user_id, product_id, quantity))

    conn.commit()
    conn.close()
    return redirect(url_for('basket'))

@app.route('/basket')
def basket():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    user_email = session['user_email']
    conn = get_db_connection()
    cursor = conn.cursor()
    user_id = get_user_id(user_email, cursor)
    cursor.execute('''
        SELECT basket.id AS basket_id, products.name, products.price, basket.quantity
        FROM basket
        JOIN products ON basket.product_id = products.id
        WHERE basket.user_id = ?
    ''', (user_id,))
    basket_items = cursor.fetchall()
    conn.close()
    return render_template('basket.html', basket_items=basket_items)

@app.route('/remove_from_basket/<int:basket_id>', methods=['POST'])
def remove_from_basket(basket_id):
    if 'user_email' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM basket WHERE id = ?', (basket_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('basket'))

@app.route('/checkout', methods=['POST'])
def checkout():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    visa_card = request.form.get('visa_card', '').strip()
    expiry_date = request.form.get('expiry_date', '').strip()
    cvv = request.form.get('cvv', '').strip()

    if not (visa_card.isdigit() and len(visa_card) == 16):
        return "Invalid Visa card number", 400
    if not re.match(r'^\d{2}/\d{2}$', expiry_date):
        return "Invalid expiry date format. Use MM/YY.", 400
    if not (cvv.isdigit() and len(cvv) == 3):
        return "Invalid CVV", 400

    conn = get_db_connection()
    cursor = conn.cursor()
    user_email = session['user_email']
    user_id = get_user_id(user_email, cursor)

    cursor.execute('''
        SELECT product_id, quantity, (quantity * price) AS total_price
        FROM basket
        JOIN products ON basket.product_id = products.id
        WHERE basket.user_id = ?
    ''', (user_id,))
    basket_items = cursor.fetchall()

    for item in basket_items:
        cursor.execute('INSERT INTO purchase_history (user_id, product_id, quantity, total_price) VALUES (?, ?, ?, ?)',
                       (user_id, item['product_id'], item['quantity'], item['total_price']))

    cursor.execute('DELETE FROM basket WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('purchase_history'))

@app.route('/purchase_history')
def purchase_history():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    user_email = session['user_email']
    user_id = get_user_id(user_email, cursor)

    cursor.execute('''
        SELECT products.name, products.price, purchase_history.quantity, purchase_history.total_price, purchase_history.purchased_at
        FROM purchase_history
        JOIN products ON purchase_history.product_id = products.id
        WHERE purchase_history.user_id = ?
    ''', (user_id,))
    purchase_history_items = cursor.fetchall()
    conn.close()
    return render_template('purchase_history.html', purchase_history_items=purchase_history_items)


@app.route('/user_setting', methods=['GET', 'POST'])
def user_setting():
    if 'user_email' not in session:
        return redirect(url_for('login'))
    user_email = session['user_email']
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch products from the database
    cursor.execute('SELECT id, name FROM products')
    raw_products = cursor.fetchall()

    # Convert SQLite Row objects to dictionaries
    products = [{'id': row['id'], 'name': row['name']} for row in raw_products]

    conn.close()
    return render_template('user_setting.html', user_email=user_email, products=products)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        if new_password != confirm_new_password:
            return "Passwords do not match", 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (session['user_email'],))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(current_password.encode('utf-8'), user['password'].encode('utf-8')):
            hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_new_password, session['user_email']))
            conn.commit()
            conn.close()
            return redirect(url_for('user_setting'))
        else:
            return "Incorrect current password", 400
    return render_template('change_password.html')


@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Delete user and associated data
    cursor.execute('DELETE FROM users WHERE email = ?', (session['user_email'],))
    cursor.execute('DELETE FROM basket WHERE user_id = (SELECT id FROM users WHERE email = ?)', (session['user_email'],))
    cursor.execute('DELETE FROM purchase_history WHERE user_id = (SELECT id FROM users WHERE email = ?)', (session['user_email'],))
    conn.commit()
    conn.close()

    session.clear()  # Clear session
    return redirect(url_for('homepage', success="Account deleted successfully!"))  # Redirect to homepage with a success message
@app.route('/write_review', methods=['POST'])
def write_review():
    if 'user_email' not in session:
        flash("You need to log in to write a review.", "error")
        return redirect(url_for('login'))

    product_id = request.form.get('product_id')
    review_text = request.form.get('review_text')
    rating = request.form.get('rating')

    if not product_id or not review_text or not rating:
        flash("All fields are required.", "error")
        return redirect(url_for('user_setting'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user ID
        cursor.execute('SELECT id FROM users WHERE email = ?', (session['user_email'],))
        user = cursor.fetchone()
        if not user:
            flash("User not found.", "error")
            return redirect(url_for('user_setting'))
        user_id = user['id']

        # Insert review into the database
        cursor.execute(
            '''
            INSERT INTO reviews (product_id, user_id, review_text, rating, review_date)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''',
            (product_id, user_id, review_text, rating)
        )
        conn.commit()
        conn.close()

        flash("Review submitted successfully.", "success")
        return redirect(url_for('user_setting'))

    except Exception as e:
        app.logger.error(f"Error submitting review: {e}")
        flash("Failed to submit review.", "error")
        return redirect(url_for('user_setting'))


@app.route('/product_reviews')
def product_reviews():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT reviews.review_text, reviews.rating, reviews.created_at, products.name AS product_name
        FROM reviews
        JOIN products ON reviews.product_id = products.id
    ''')
    reviews = cursor.fetchall()
    conn.close()
    return render_template('productreview.html', reviews=reviews)


@app.errorhandler(400)
def bad_request_error(e):
    app.logger.error(f"Bad Request: {str(e)}")
    return jsonify({"error": "Bad Request"}), 400

@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
    return response

if __name__ == '__main__':
    app.run(debug=True, port=8080)
