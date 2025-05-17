from flask import Flask,flash, render_template, request, redirect, url_for, session
import pyodbc, hashlib, re
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'ass1gn'

conn_str = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=DE_DRAGON\SQLEXPRESS;" # Change this if needed (e.g., IP address or hostname)
    "DATABASE=SportsInventory;"
    "Trusted_Connection=yes;"
)

def get_db():
    return pyodbc.connect(conn_str)

@app.route('/')
def login():
    return render_template('Login.html')

@app.route('/login', methods=['GET', 'POST'])
def do_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        hashed_password = hashlib.sha512(password.encode('utf-8')).digest()

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, role FROM Users WHERE email=? AND PasswordHash=?", (email, hashed_password))
        user = cursor.fetchone()
        conn.close()
        if user:
            user_id, role = user
            session['user_id'] = user_id
            session['role'] = role 

            if role == 'admin':
                return redirect('/admin')
            else:
                return redirect('/dashboard')

        flash("Invalid email or password", "danger")
        return redirect('/login')
    return render_template('Login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name'].strip()
        student_id = request.form['student_id'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        # Simple validations
        if not full_name:
            flash("Full name is required.")
            return redirect('/register')
        
        if not re.match(r'^[A-Za-z0-9]+$', student_id):
            flash("Student ID must be alphanumeric.")
            return redirect('/register')

        email_regex = r'^[^@]+@[^@]+\.[^@]+$'
        if not re.match(email_regex, email):
            flash("Invalid email address.")
            return redirect('/register')

        if len(password) < 6:
            flash("Password must be at least 6 characters.")
            return redirect('/register')

        # Hash the password as binary
        hashed_password = hashlib.sha512(password.encode('utf-8')).digest()  # returns 64-byte binary
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if user already exists by email or student_id
        cursor.execute("SELECT id FROM Users WHERE email = ? OR student_id = ?", (email, student_id))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            return "Email or Student ID already registered"
        
        # Insert new user
        cursor.execute("""
            INSERT INTO Users (full_name, student_id, email, PasswordHash)
            VALUES (?, ?, ?, ?)
        """, (full_name, student_id, email, hashed_password))
        
        conn.commit()
        conn.close()
        
        return redirect('/login')
    
    return render_template('Register.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    # Only allow access if the user is logged in and is an admin
    if 'user_id' not in session:
        flash('Please log in to access the admin panel.', 'warning')
        return redirect(url_for('do_login'))

    conn = get_db()
    cursor = conn.cursor()

    # Adding Equipment
    if request.method == 'POST':
        name = request.form['EqName']
        category = request.form['category']
        quantity = request.form['quantity']

        cursor.execute(
            "INSERT INTO Equipment (name, category, quantity) VALUES (?, ?, ?)",
            (name, category, quantity)
        )
        conn.commit()
        flash('Equipment added successfully.', 'success')

    # Fetch all equipment for display
    cursor.execute("SELECT * FROM Equipment")
    equipment = cursor.fetchall()
    
    # Fetch rental records
    cursor.execute("""
        SELECT TOP 20 U.full_name, U.student_id, E.name, R.quantity, R.date_rented, R.returned
        FROM Rentals R
        JOIN Users U ON R.user_id = U.id
        JOIN Equipment E ON R.equipment_id = E.id
        ORDER BY R.date_rented DESC, R.id DESC
    """)
    records = cursor.fetchall()
    conn.close()

    return render_template('Admin.html', equipment=equipment, records=records)

@app.route('/edit_equipment', methods=['POST'])
def edit_equipment():
    equipment_id = request.form['id']
    name = request.form['name']
    category = request.form['category']
    quantity = request.form['quantity']

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE Equipment
        SET name = ?, category = ?, quantity = ?
        WHERE id = ?
    """, (name, category, quantity, equipment_id))
    conn.commit()
    conn.close()
    return redirect('/admin')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    return render_template('StudentDashboard.html')

@app.route('/equipment')
def show_equipment():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, quantity FROM Equipment WHERE quantity > 0")
    equipment = cursor.fetchall()
    conn.close()

@app.route('/rent/<int:equipment_id>', methods=['POST'])
def rent_equipment(equipment_id):
    if 'user_id' not in session:
        return redirect('/')
    
    quantity = int(request.form.get('quantity', 1))
    user_id = session['user_id']
    today = datetime.now().date()
    due = today + timedelta(days=7)

    conn = get_db()
    cursor = conn.cursor()

    # Ensure enough stock is available
    cursor.execute("SELECT quantity FROM Equipment WHERE id = ?", (equipment_id,))
    available = cursor.fetchone()
    if not available or available[0] < quantity:
        conn.close()
        return "Not enough equipment available", 400

    # Add rental and update quantity
    cursor.execute("""
        INSERT INTO Rentals (user_id, equipment_id, date_rented, due_date, quantity)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, equipment_id, today, due, quantity))

    cursor.execute("UPDATE Equipment SET quantity = quantity - ? WHERE id = ?", (quantity, equipment_id))
    
    conn.commit()
    conn.close()

    return redirect('/dashboard')

@app.route('/browse')
def browse_equipment():
    if 'user_id' not in session:
        return redirect('/')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Equipment WHERE quantity > 0")
    equipment = cursor.fetchall()
    conn.close()
    return render_template('BrowseEquipment.html', equipment=equipment)

@app.route('/myrentals')
def my_rentals():
    if 'user_id' not in session:
        return redirect('/')
    user_id = session['user_id']
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT R.id, E.name, R.date_rented, R.due_date 
        FROM Rentals R
        JOIN Equipment E ON R.equipment_id = E.id
        WHERE R.user_id=? AND R.returned=0
    """, (user_id,))
    rentals = cursor.fetchall()
    conn.close()
    return render_template('MyRental.html', rentals=rentals)

@app.route('/return/<int:rental_id>', methods=['POST'])
def return_rental(rental_id):
    conn = get_db()
    cursor = conn.cursor()

    # Get the equipment_id and quantity rented to update inventory correctly
    cursor.execute("SELECT equipment_id, quantity FROM Rentals WHERE id = ?", (rental_id,))
    row = cursor.fetchone()
    if row:
        equip_id, rented_quantity = row
        # Mark rental as returned
        cursor.execute("UPDATE Rentals SET returned = 1 WHERE id = ?", (rental_id,))
        # Restore the full quantity rented back to the equipment stock
        cursor.execute("UPDATE Equipment SET quantity = quantity + ? WHERE id = ?", (rented_quantity, equip_id))
        conn.commit()

    conn.close()
    return redirect('/myrentals')

if __name__ == '__main__':
    app.run(debug=True)
