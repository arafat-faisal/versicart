# app.py
import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import datetime
from werkzeug.utils import secure_filename # Corrected: Added this import

# Initialize the Flask application
app = Flask(__name__)

# --- Configuration ---
# Set a secret key for session management and Flask-Login.
# IMPORTANT: In a production environment, this should be a complex, random string
# and stored securely (e.g., environment variable).
app.secret_key = 'your_super_secret_key_change_this_in_production'

# Directory where uploaded images will be stored
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Allowed image file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
# Path for the SQLite database file
DATABASE = 'ecommerce.db' # Renamed to avoid conflicts and represent a broader scope

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # The view Flask-Login should redirect to for login

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    @staticmethod
    def get(user_id):
        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['password'])
        return None

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# --- Database Initialization ---
def get_db_connection():
    """Establishes a connection to the SQLite database."""
    # Using g.db to ensure only one connection per request
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # This allows accessing columns by name
    return g.db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database schema if it doesn't exist."""
    conn = get_db_connection()
    # Create the products table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            image_url TEXT
        )
    ''')
    # Create the users table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    # Create the carts table (for persistent user carts)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS carts (
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            PRIMARY KEY (user_id, product_id),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE
        )
    ''')
    # Create the orders table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            order_date TEXT NOT NULL,
            total_amount REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    # Create the order_items table (details for each order)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            price_at_purchase REAL NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE
        )
    ''')
    conn.commit()

    # Add initial products if the table is empty (optional, for demo)
    cursor = conn.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        initial_products = [
            ('Stylish Backpack', 'Durable and spacious backpack for daily use.', 49.99, 'https://placehold.co/400x300/F0F0F0/000000?text=Backpack'),
            ('Wireless Headphones', 'High-quality sound with comfortable ear cups.', 79.99, 'https://placehold.co/400x300/F0F0F0/000000?text=Headphones'),
            ('Smartwatch', 'Track your fitness and receive notifications.', 129.99, 'https://placehold.co/400x300/F0F0F0/000000?text=Smartwatch')
        ]
        conn.executemany("INSERT INTO products (name, description, price, image_url) VALUES (?, ?, ?, ?)", initial_products)
        conn.commit()
    # No initial users for security reasons; users should register.
    conn.close()

# Initialize the database when the app starts
with app.app_context():
    init_db()

# --- Helper Functions ---
def allowed_file(filename):
    """Checks if a file's extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Routes ---

@app.route('/')
def index():
    """Renders the main product listing page, fetching products from the database."""
    conn = get_db_connection()
    products_db = conn.execute('SELECT * FROM products').fetchall()
    # conn.close() # Managed by @app.teardown_appcontext

    # Convert sqlite3.Row objects to dictionaries for easier access in template
    products = [dict(row) for row in products_db]
    return render_template('index.html', products=products)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    """Displays a single product's detailed information."""
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    # conn.close() # Managed by @app.teardown_appcontext

    if product is None:
        flash('Product not found.', 'error')
        return redirect(url_for('index'))
    return render_template('product_detail.html', product=dict(product))


@app.route('/add_product', methods=['GET', 'POST'])
@login_required # Only logged-in users can add products
def add_product():
    """Handles adding new products to the database."""
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        try:
            price = float(request.form['price'])
        except ValueError:
            flash('Invalid price format. Please enter a valid number.', 'error')
            return redirect(url_for('add_product'))

        image_file = request.files.get('image')

        image_filename = None
        if image_file and image_file.filename != '' and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)
            image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_filename = filename
        else:
            # Fallback to a generic placeholder if no valid image is uploaded
            image_filename = 'placeholder.png' # Ensure you have a placeholder.png in static/uploads

        # Construct the image URL based on whether an image was uploaded or a placeholder is used
        image_url = url_for('static', filename=f'uploads/{image_filename}')

        conn = get_db_connection()
        conn.execute('INSERT INTO products (name, description, price, image_url) VALUES (?, ?, ?, ?)',
                     (name, description, price, image_url))
        conn.commit()
        flash(f'Product "{name}" added successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('add_product.html')

@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required # Only logged-in users can edit products
def edit_product(product_id):
    """Handles editing an existing product."""
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()

    if product is None:
        flash('Product not found.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        try:
            price = float(request.form['price'])
        except ValueError:
            flash('Invalid price format. Please enter a valid number.', 'error')
            return redirect(url_for('edit_product', product_id=product_id))

        image_file = request.files.get('image')
        image_url = product['image_url'] # Default to existing image URL

        if image_file and image_file.filename != '' and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)
            image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = url_for('static', filename=f'uploads/{filename}')
        # No else needed; if no new valid image, image_url remains the existing one

        conn.execute('UPDATE products SET name = ?, description = ?, price = ?, image_url = ? WHERE id = ?',
                     (name, description, price, image_url, product_id))
        conn.commit()
        flash(f'Product "{name}" updated successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('edit_product.html', product=dict(product))

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required # Only logged-in users can delete products
def delete_product(product_id):
    """Handles deleting a product from the database."""
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    if product:
        conn.execute('DELETE FROM products WHERE id = ?', (product_id,))
        conn.commit()
        flash(f'Product "{product["name"]}" deleted successfully!', 'success')
    else:
        flash('Product not found.', 'error')
    return redirect(url_for('index'))

@app.route('/add_to_cart/<int:product_id>')
@login_required # Only logged-in users can add to cart
def add_to_cart(product_id):
    """Adds a product to the user's persistent cart."""
    user_id = current_user.id
    conn = get_db_connection()

    # Check if product exists
    product_exists = conn.execute('SELECT 1 FROM products WHERE id = ?', (product_id,)).fetchone()
    if not product_exists:
        flash('Product not found.', 'error')
        return redirect(url_for('index'))

    # Check if item is already in cart for this user
    cart_item = conn.execute('SELECT quantity FROM carts WHERE user_id = ? AND product_id = ?',
                             (user_id, product_id)).fetchone()

    if cart_item:
        # If exists, update quantity
        new_quantity = cart_item['quantity'] + 1
        conn.execute('UPDATE carts SET quantity = ? WHERE user_id = ? AND product_id = ?',
                     (new_quantity, user_id, product_id))
        flash(f'Increased quantity for item in cart!', 'success')
    else:
        # If not exists, add new item
        conn.execute('INSERT INTO carts (user_id, product_id, quantity) VALUES (?, ?, ?)',
                     (user_id, product_id, 1))
        flash(f'Item added to cart!', 'success')
    conn.commit()
    return redirect(url_for('index'))

@app.route('/remove_from_cart/<int:product_id>')
@login_required
def remove_from_cart(product_id):
    """Removes a product from the user's persistent cart (decrements quantity or removes entirely)."""
    user_id = current_user.id
    conn = get_db_connection()
    cart_item = conn.execute('SELECT quantity FROM carts WHERE user_id = ? AND product_id = ?',
                             (user_id, product_id)).fetchone()

    if cart_item:
        if cart_item['quantity'] > 1:
            conn.execute('UPDATE carts SET quantity = ? WHERE user_id = ? AND product_id = ?',
                         (cart_item['quantity'] - 1, user_id, product_id))
            flash('Decreased quantity for item in cart!', 'success')
        else:
            conn.execute('DELETE FROM carts WHERE user_id = ? AND product_id = ?',
                         (user_id, product_id))
            flash('Item removed from cart!', 'success')
        conn.commit()
    else:
        flash('Item not found in cart.', 'error')
    return redirect(url_for('cart'))

@app.route('/cart')
@login_required
def cart():
    """Displays the contents of the shopping cart for the logged-in user."""
    user_id = current_user.id
    conn = get_db_connection()
    cart_items_db = conn.execute('''
        SELECT p.id, p.name, p.description, p.price, p.image_url, c.quantity
        FROM carts c JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ?
    ''', (user_id,)).fetchall()

    products_in_cart = []
    total_price = 0

    for item in cart_items_db:
        item_dict = dict(item)
        item_dict['subtotal'] = item_dict['price'] * item_dict['quantity']
        products_in_cart.append(item_dict)
        total_price += item_dict['subtotal']

    # conn.close() # Managed by @app.teardown_appcontext
    if not products_in_cart and request.args.get('flash_empty_cart') != 'false': # Prevent flashing on redirect
        flash('Your cart is empty!', 'info')

    return render_template('cart.html', products_in_cart=products_in_cart, total_price=total_price)


@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    """Processes the checkout, converting cart items into an order."""
    user_id = current_user.id
    conn = get_db_connection()

    cart_items_db = conn.execute('SELECT product_id, quantity FROM carts WHERE user_id = ?', (user_id,)).fetchall()

    if not cart_items_db:
        flash('Your cart is empty. Cannot checkout.', 'error')
        return redirect(url_for('cart', flash_empty_cart='false'))

    total_amount = 0
    order_items_data = []

    for item in cart_items_db:
        product = conn.execute('SELECT price FROM products WHERE id = ?', (item['product_id'],)).fetchone()
        if product:
            price_at_purchase = product['price']
            subtotal = price_at_purchase * item['quantity']
            total_amount += subtotal
            order_items_data.append({
                'product_id': item['product_id'],
                'quantity': item['quantity'],
                'price_at_purchase': price_at_purchase
            })

    # Create the order
    order_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor = conn.execute('INSERT INTO orders (user_id, order_date, total_amount) VALUES (?, ?, ?)',
                         (user_id, order_date, total_amount))
    order_id = cursor.lastrowid # Get the ID of the newly created order

    # Add order items
    for item_data in order_items_data:
        conn.execute('INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) VALUES (?, ?, ?, ?)',
                     (order_id, item_data['product_id'], item_data['quantity'], item_data['price_at_purchase']))

    # Clear the cart after successful checkout
    conn.execute('DELETE FROM carts WHERE user_id = ?', (user_id,))
    conn.commit()

    flash(f'Order #{order_id} placed successfully! Total: ${total_amount:.2f}', 'success')
    return redirect(url_for('orders'))

@app.route('/orders')
@login_required
def orders():
    """Displays the order history for the logged-in user."""
    user_id = current_user.id
    conn = get_db_connection()
    orders_db = conn.execute('SELECT * FROM orders WHERE user_id = ? ORDER BY order_date DESC', (user_id,)).fetchall()

    user_orders = []
    for order in orders_db:
        order_dict = dict(order)
        # Fetch items for each order
        items_db = conn.execute('''
            SELECT oi.quantity, oi.price_at_purchase, p.name, p.image_url
            FROM order_items oi JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id = ?
        ''', (order['id'],)).fetchall()
        order_dict['items'] = [dict(item) for item in items_db]
        user_orders.append(order_dict)

    # conn.close() # Managed by @app.teardown_appcontext
    if not user_orders:
        flash('You have no past orders.', 'info')
    return render_template('orders.html', orders=user_orders)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.', 'error')
        finally:
            pass # conn is managed by @app.teardown_appcontext

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        # conn.close() # Managed by @app.teardown_appcontext

        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data['id'], user_data['username'], user_data['password'])
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(request.args.get('next') or url_for('index'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logs out the current user."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


# Run the Flask application
if __name__ == '__main__':
    # When running locally and DATABASE already exists,
    # you might want to uncomment the following lines to reset the DB for development:
    # if os.path.exists(DATABASE):
    #     os.remove(DATABASE)
    # with app.app_context():
    #     init_db()
    app.run(debug=True)
