import os
import uuid
import string
import qrcode
import base64
import json
from PIL import Image
from flask_cors import cross_origin
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import atexit
import logging
import random
import sqlite3
from io import BytesIO
from datetime import date
from flask_cors import CORS
from flask import Flask, request, jsonify
# from apscheduler.schedulers.background import BackgroundScheduler
import jwt
import datetime
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"*": {"origins": "*"}})

SECRET_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsInVzZXJuYW1lIjoicmFuZG9tdXNlciIsImV4cCI6MTcxMTQzOTAwMH0.TwS7J8WqOZpTMTZ6E'

import sqlite3

DB_PATH = "/MainDatabase.db"  

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Identify table for user login
    cursor.execute('''CREATE TABLE IF NOT EXISTS users ( 
        ad TEXT,
        soyad TEXT,
        digimealusername TEXT, 
        password TEXT,
        fakulte TEXT, 
        approved TEXT 
        email TEXT
    )''')

    # QR Code table
    cursor.execute('''CREATE TABLE IF NOT EXISTS qr_codes ( 
        id TEXT PRIMARY KEY, 
        username TEXT, 
        image BLOB, 
        date TEXT, 
        status INTEGER DEFAULT 1, 
        status_scanner INTEGER DEFAULT 1, 
        scanner_time TEXT,
        scanner_status TEXT,
        FOREIGN KEY (username) REFERENCES identify(username) 
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS all_users (
        ad TEXT,
        soyad TEXT,
        ata_adi TEXT,
        fin_kod TEXT UNIQUE, 
        telefon_nomresi TEXT,
        fakulte TEXT,
        qrup_no TEXT,
        status TEXT,
        bilet INTEGER,
        email TEXT,
        approved INTEGER,
        digimealusername INTEGER,
        otp INTEGER,
        password TEXT,
        document BLOB,
        qeydiyyat_tarixi TEXT,
        qeyd TEXT           
    )''')

    # Scanner login table
    cursor.execute('''CREATE TABLE IF NOT EXISTS scanner_identification (
        scanner_username TEXT , 
        scanner_password TEXT L 
        scanner_istifadeci_adi TEXT, 
        faculty TEXT 
    )''')

    cursor.execute(''' CREATE TABLE IF NOT EXISTS adminsidenfication (
        usernameadmin TEXT,
        passwordadmin TEXT,
        istifadeci_adi TEXT,
        faculty TEXT
    )''')

    conn.commit()
    conn.close()

init_db()


# JWT token generation
def generate_jwt(username, is_admin=False, is_scanner = False):
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=10)
    payload = {
        'username': username,
        'is_admin': is_admin,
        'scanner': is_scanner,
        'exp': expiration_time
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def check_scanner_login(scanner_username, scanner_password):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scanner_identification WHERE scanner_username = ? AND scanner_password = ?", 
                       (scanner_username, scanner_password))
        scanner = cursor.fetchone()
        if scanner:
            token = generate_jwt(scanner_username, is_admin=False, is_scanner=True)
            return {"success": True, "username": scanner_username, "message": "Login successful", "token": token}
        else:
            return {"success": False, "message": "Incorrect username or password"}
    finally:
        conn.close()

# Function to check user login
def check_login(username, password):
    logging.debug(f"Attempting login for username: {username}")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Log the query parameters
        logging.debug(f"Executing query with username={username} and password={password}")

        cursor.execute("SELECT * FROM users WHERE digimealusername = ? AND password = ? AND approved = ?", 
                       (username, password, 1))
        user = cursor.fetchone()

        if user:
            token = generate_jwt(username)
            logging.info(f"Login successful for username: {username}")
            return {"success": True, "username": username, "message": "Login successful", "token": token}
        else:
            logging.warning(f"Login failed for username: {username} - Incorrect credentials or not approved")
            return {"success": False, "message": "Incorrect username or password"}
    
    except sqlite3.Error as e:
        logging.error(f"Database error during login for {username}: {str(e)}")
        return {"success": False, "message": f"Database error: {str(e)}"}
    
    finally:
        conn.close()
        logging.debug(f"Database connection closed for username: {username}")


# Function to check admin login
def check_admin_login(username, password):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM adminsidenfication WHERE usernameadmin = ? AND passwordadmin = ?", (username, password))
        admin = cursor.fetchone()
        if admin:
            token = generate_jwt(username, is_admin=True)
            return {"success": True, "username": username, "message": "Login successful", "token": token}
        else:
            return {"success": False, "message": "Incorrect username or password"}
    finally:
        conn.close()
def generate_otp():
    return str(random.randint(100000, 999999))
def send_otp(receiver_email, username, otp):
    sender_email = "thik@aztu.edu.az"
    sender_password = "xjxi kknj rvmt sciz"

    # otp = generate_otp()
    # Email content
    subject = "Sizin OTP kodunuz!"
    body = f"Sizin bir dəfəlik OTP kodunuz: {otp}\n\n Bu OTP kodu 5 dəqiqə ərzində aktivdir. \n\n İstifadəçi adı: {username} \n\n Link: http://192.168.171.192:3000/user-pass-creater?"

    # Setup email headers
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    # Attach email body
    message.attach(MIMEText(body, "plain"))

    # Secure connection with Gmail SMTP server
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, message.as_string())

        print(f"OTP sent successfully to {receiver_email}")
        return otp  # Return OTP for verification

    except Exception as e:
        print(f"Error sending OTP: {e}")
        return None

def generate_username():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT MAX(CAST(digimealusername AS INTEGER)) FROM all_users")
        result = cursor.fetchone()[0]
        if result is None:
            return 20250000
        return int(result) + 1
    except Exception as e:
        print(f"Error generating username: {e}")
        return None
    finally:
        conn.close()

# Generate a random password
# def generate_pass_for_user():
#     letters_and_digits = string.ascii_letters + string.digits
#     symbols = string.punctuation

#     password = random.choice(symbols)
#     password += ''.join(random.choice(letters_and_digits) for _ in range(7))
#     password = ''.join(random.sample(password, len(password)))

#     return password

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            token = token.split(" ")[1]  # Extract token part from "Bearer <token>"
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user = payload['username']
            is_admin = payload['is_admin']
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({'message': 'Token is invalid!'}), 403

        # Add user info to the request context
        request.current_user = current_user
        request.is_admin = is_admin
        return f(*args, **kwargs)

    return decorated_function


# Routes for user and admin login
@app.route('/user/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required"}), 400

    result = check_login(username, password)
    return jsonify(result), 200 if result['success'] else 401


@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required"}), 400
    result = check_admin_login(username, password)
    return jsonify(result), 200 if result['success'] else 401

@app.route('/admin/get_admin_username', methods=['POST'])
@token_required
def get_admin_username():
    # Ensure the request is from an admin user
    if not request.is_admin:
        return jsonify({"success": False, "message": "Admin access required"}), 403

    data = request.json
    usernameadmin = data.get('usernameadmin')

    if not usernameadmin:  # Ensuring 'usernameadmin' is provided
        return jsonify({"success": False, "message": "Username is required"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # Query to fetch the admin data
        cursor.execute('SELECT istifadeci_adi, faculty FROM adminsidenfication WHERE usernameadmin = ?', (usernameadmin,))
        result = cursor.fetchall()  # Fetch all matching rows

        # Format the results for response
        results_for_admin = [{"istifadeciadi": row[0], "faculty": row[1]} for row in result]

        if results_for_admin:  # Check if results exist
            return jsonify({"success": True, "results": results_for_admin}), 200
        else:
            return jsonify({"success": False, "message": "Username not found"}), 404
    except sqlite3.Error as e:
        # Handle database errors
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    finally:
        # Close the database connection
        conn.close()

#working code for fac admin registiration
@app.route('/add', methods=['POST'])
@token_required
def add():
    try:
        # Parse and validate request data
        data = request.json
        print("Received data:", data)  # Debugging line to show the received data
        
        required_fields = ['firstname', 'lastname', 'fathername', 'fincode', 'phonenumber', 'fakulte', 
                           'groupnumber', 'status', 'bilet', 'email', 'registrationDate', 'note']
        
        # Check for missing fields
        for field in required_fields:
            if field not in data or not data[field]:
                print(f"Missing field: {field}")  # Debugging line for missing fields
                return jsonify({"error": f"'{field}' is required."}), 400
        
        # Extract fields
        firstname = data['firstname']
        lastname = data['lastname']
        fathername = data['fathername']
        fincode = data['fincode']
        phonenumber = data['phonenumber']
        fakulte = data['fakulte']
        qrup_no = data['groupnumber']
        status = data['status']
        bilet = data['bilet']
        email = data['email']
        registrationDate = data['registrationDate']  # ✅ Fixed typo
        note = data['note']
        
        print(f"Extracted data: {firstname}, {lastname}, {fincode}, {phonenumber}")  # Debugging line for extracted data
        
        # Database operations with context manager
        with sqlite3.connect(DB_PATH) as conn:
            print(f"Database connection established: {conn}")  # Debugging line for DB connection
            
            cursor = conn.cursor()
            print("Cursor created.")  # Debugging line for cursor
            
            # Prepare JSON structure for sessiya
            sessiya_json = json.dumps({"session_start": registrationDate})

            # Insert into all_users
            try:
                cursor.execute(''' 
                    INSERT INTO all_users (ad, soyad, ata_adi, fin_kod, telefon_nomresi, fakulte, qrup_no, 
                                           status, bilet, email, qeyd, approved, sessiya, qeydiyyat_tarixi)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (firstname, lastname, fathername, fincode, phonenumber, fakulte, qrup_no, 
                      status, bilet, email, note, 0, sessiya_json, registrationDate))
                print("Record inserted into all_users.")  # Debugging line
            except sqlite3.IntegrityError as e:
                print(f"IntegrityError while inserting into all_users: {str(e)}")  # Debugging line for error
                raise e  # Raise the exception to be caught by outer exception
            
            # Insert into users
            try:
                cursor.execute(''' 
                    INSERT INTO users (ad, soyad, status, email, fakulte, approved, status, email, fin_kod)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (firstname, lastname, status, email, fakulte, 1, status, email, fincode))
                print("Record inserted into users.")  # Debugging line
            except sqlite3.IntegrityError as e:
                print(f"IntegrityError while inserting into users: {str(e)}")  # Debugging line for error
                raise e  # Raise the exception to be caught by outer exception
            
            conn.commit()
            print("Changes committed to the database.")  # Debugging line for commit
        
        return jsonify({"message": "Record added successfully."}), 201
    
    except sqlite3.IntegrityError as e:
        print(f"IntegrityError occurred: {str(e)}")  # Debugging line for IntegrityError
        logging.error(f"IntegrityError: {str(e)}")  # Logging the error
        return jsonify({"error": "Duplicate entry. The fin_kod or email might already exist."}), 400
    
    except sqlite3.Error as e:
        print(f"SQLite error occurred: {str(e)}")  # Debugging line for SQLite error
        logging.error(f"SQLite error: {str(e)}")  # Logging the error
        return jsonify({"error": "Database error occurred.", "details": str(e)}), 500
    
    except Exception as e:
        print(f"Unexpected error occurred: {str(e)}")  # Debugging line for unexpected error
        logging.error(f"Unexpected error: {str(e)}")  # Logging the error
        return jsonify({"error": "An unexpected error occurred.", "details": str(e)}), 502




@app.route('/notapproved/<faculty>', methods=['GET'])
@token_required
def get_not_approved_students(faculty):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT ad, soyad, ata_adi, digimealusername, fin_kod, telefon_nomresi, fakulte, qrup_no, status, bilet, email FROM all_users WHERE fakulte = ? AND approved = 0', 
            (faculty,)
        )
        rows = cursor.fetchall()
        print(f"Rows fetched for faculty '{faculty}':", rows)  # Debugging line
        conn.close()
        
        if rows:
            result = [
                {
                    "ad": row[0],
                    "soyad": row[1],
                    "ata_adi": row[2],
                    "digimealusername": row[3],
                    "fin_kod": row[4],
                    "phonenumber": row[5],
                    "fakulte": row[6],
                    "qrup_no": row[7],
                    "status": row[8],
                    "bilet": row[9],
                    "email": row[10],
                }
                for row in rows
            ]
            return {"results": result}, 200
        else:
            return {"message": "No students found for the specified faculty."}, 404
    except sqlite3.Error as e:
        return {"error": str(e)}, 500
    
# faculty/super admin approved users route
@app.route('/fac_approved/<faculty>', methods=['GET'])
@token_required
def fac_get_approved_students(faculty):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT ad, soyad, ata_adi, digimealusername, fin_kod, telefon_nomresi, fakulte, qrup_no, status, bilet, email, qeyd FROM all_users WHERE fakulte = ? AND approved = 1', 
            (faculty,)
        )
        rows = cursor.fetchall()
        print(f"Rows fetched for faculty '{faculty}':", rows)  # Debugging line
        conn.close()
        
        if rows:
            result = [
                {
                    "ad": row[0],
                    "soyad": row[1],
                    "ata_adi": row[2],
                    "digimealusername": row[3],
                    "fin_kod": row[4],
                    "phonenumber": row[5],
                    "fakulte": row[6],
                    "qrup_no": row[7],
                    "status": row[8],
                    "bilet": row[9],
                    "email": row[10],
                    "qeyd": row[11]
                    
                }
                for row in rows
            ]
            return {"results": result}, 200
        else:
            return {"message": "No students found for the specified faculty."}, 404
    except sqlite3.Error as e:
        return {"error": str(e)}, 500

# Super Admin approved users route
@app.route('/superadmin_approved/', methods=['GET'])
@token_required
def get_approved_students_sp_admin():
    try:
        print("Attempting to fetch approved students...")  # Debugging line
        
        with sqlite3.connect(DB_PATH) as conn:
            print(f"Database connection established: {conn}")  # Debugging line
            
            cursor = conn.cursor()
            print("Cursor created.")  # Debugging line
            
            # Execute query
            cursor.execute(
                'SELECT ad, soyad, ata_adi, digimealusername, fin_kod, telefon_nomresi, fakulte, qrup_no, status, bilet, email, qeyd FROM all_users WHERE approved = 1'
            )
            print("SQL query executed successfully.")  # Debugging line
            
            rows = cursor.fetchall()
            print(f"Rows fetched: {rows}")  # Debugging line
            
        # Process rows
        if rows:
            print(f"Processing {len(rows)} rows...")  # Debugging line
            result = [
                {
                    "ad": row[0],
                    "soyad": row[1],
                    "ata_adi": row[2],
                    "digimealusername": row[3],
                    "fin_kod": row[4],
                    "phonenumber": row[5],
                    "fakulte": row[6],
                    "qrup_no": row[7],
                    "status": row[8],
                    "bilet": row[9],
                    "email": row[10],
                    "qeyd": row[11]
                }
                for row in rows
            ]
            print(f"Returning {len(result)} processed rows.")  # Debugging line
            return {"results": result}, 200
        else:
            print("No rows found, returning empty list.")  # Debugging line
            return {"results": []}, 200

    except sqlite3.Error as e:
        print(f"SQLite error occurred: {str(e)}")  # Debugging line
        return {"error": "Database error", "details": str(e)}, 500
    
    except Exception as e:
        print(f"Unexpected error occurred: {str(e)}")  # Debugging line
        return {"error": "Unexpected error", "details": str(e)}, 500


# Super Admin Session ended users
@app.route('/superadmin_session_ended/', methods=['GET'])
@token_required
def get_session_ended_students_sp_admin():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT ad, soyad, ata_adi, digimealusername, fin_kod, telefon_nomresi, fakulte, qrup_no, status, bilet, email FROM all_users WHERE approved = 2'
            )
            rows = cursor.fetchall()
            print(f"Rows fetched for faculty: {rows}")
        
        if rows:
            result = [
                {
                    "ad": row[0],
                    "soyad": row[1],
                    "ata_adi": row[2],
                    "digimealusername": row[3],
                    "fin_kod": row[4],
                    "phonenumber": row[5],
                    "fakulte": row[6],
                    "qrup_no": row[7],
                    "status": row[8],
                    "bilet": row[9],
                    "email": row[10]
                }
                for row in rows
            ]
            return {"results": result}, 200
        else:
            return {"results": []}, 200  
    except sqlite3.Error as e:
        return {"error": "Database error", "details": str(e)}, 500
# Super Admin waiting approved route
@app.route('/superadmin_notapproved/', methods=['GET'])
@token_required
def get_not_approved_students_sp_admin():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT ad, soyad, ata_adi, digimealusername, fin_kod, telefon_nomresi, fakulte, qrup_no, status, bilet, email FROM all_users WHERE approved = 0'
            )
            rows = cursor.fetchall()
            print(f"Rows fetched for faculty: {rows}")  
        
        if rows:
            result = [
                {
                    "ad": row[0],
                    "soyad": row[1],
                    "ata_adi": row[2],
                    "digimealusername": row[3],
                    "fin_kod": row[4],
                    "phonenumber": row[5],
                    "fakulte": row[6],
                    "qrup_no": row[7],
                    "status": row[8],
                    "bilet": row[9],
                    "email": row[10]
                }
                for row in rows
            ]
            return {"results": result}, 200
        else:
            return {"results": []}, 200  
    except sqlite3.Error as e:
        return {"error": "Database error", "details": str(e)}, 500


# @app.route('/request-otp/<email>', methods=['POST'])
# def request_otp(email):
#     if not email:
#         return jsonify({'message': 'Email is required'}), 400

#     otp = generate_otp()

#     conn = sqlite3.connect(DB_PATH)
#     cursor = conn.cursor()
#     try:
#         cursor.execute("UPDATE all_users SET otp = ? WHERE email = ?", (otp, email))
#         conn.commit()
#         return jsonify({'message': 'OTP set successfully'}), 200
#     except sqlite3.Error as e:
#         return jsonify({'message': f'Database error: {e}'}), 500
#     finally:
#         conn.close()

@app.route('/verify-otp', methods=['POST'])
# @token_required
def verify_otp():
    data = request.json
    username = data.get('username')
    otp = data.get('otp')
    password = data.get('password')
    print(password, username, otp)
    currentDate = datetime.date.today()

    if not username or not otp or not password:
        return jsonify({'message': 'Username, OTP, and password are required'}), 400

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()

            # Retrieve the OTP from the database
            cursor.execute("SELECT otp FROM all_users WHERE digimealusername = ?", (username,))
            result = cursor.fetchone()

            if result and str(result[0]) == otp:
                cursor.execute("""
                    UPDATE all_users 
                    SET approved = 1, otp = NULL, password = ?, qeydiyyat_tarixi = ?
                    WHERE digimealusername = ?
                """, (password, currentDate, username))

                # cursor.execute("""
                #     UPDATE users 
                #     SET password = ?, digimealusername =
                # """, (password, currentDate, username))

                cursor.execute("""
                    UPDATE users 
                    SET approved = 1, password = ? 
                    WHERE digimealusername = ?
                """, (password, username))

                conn.commit()

                return jsonify({
                    'message': 'OTP verified successfully',
                    'digimealusername': username
                }), 200
            else:
                return jsonify({'message': 'Invalid OTP'}), 400
    except sqlite3.Error as e:
        return jsonify({'message': f'Database error: {e}'}), 500


# sp-adm-en-session route
@app.route('/sesion_end/<digimealusername>', methods=['GET'])
@token_required
def sesion_end(digimealusername):
    current_date = datetime.date.today()
    logging.info(f"Session end requested for user: {digimealusername}")
    logging.debug(f"Current date: {current_date}")

    try:
        # Connect to the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        logging.debug("Database connection established.")
        
        # Fetch the current 'sessiya' value from the database
        cursor.execute('SELECT sessiya FROM all_users WHERE digimealusername = ?', (digimealusername,))
        result = cursor.fetchone()

        if result:
            sessiya = result[0]  # Get the stringified JSON from the database
            logging.debug(f"Current sessiya: {sessiya}")
            
            # Parse the existing JSON
            try:
                sessiya_data = json.loads(sessiya)
                logging.debug(f"Parsed sessiya data: {sessiya_data}")
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON from sessiya: {e}")
                return {"error": "Error decoding JSON from sessiya"}, 500
            
            # Add the session end date to the JSON with a dynamic key
            dynamic_key = f"sessiya_bitme_{current_date.strftime('%Y-%m-%d')}"  # Dynamic key based on the current date
            sessiya_data[dynamic_key] = current_date.strftime('%Y-%m-%d')  # Add the session end date value
            logging.debug(f"Added session end date to JSON with dynamic key: {sessiya_data}")
            
            # Stringify the updated JSON
            updated_sessiya = json.dumps(sessiya_data)
            logging.debug(f"Updated sessiya: {updated_sessiya}")
            
            # Update the 'sessiya' field in the database with the new JSON
            cursor.execute('''
                UPDATE all_users
                SET sessiya = ?, approved = ?
                WHERE digimealusername = ?
            ''', (updated_sessiya, 2, digimealusername))
            logging.debug(f"Updated sessiya and set approved = 2 for user {digimealusername} in all_users table.")
            
            # Update 'approved' field in 'users' table
            cursor.execute('UPDATE users SET approved = 2 WHERE digimealusername = ?', (digimealusername,))
            logging.debug(f"Set approved = 2 for user {digimealusername} in users table.")
            
            # Commit the changes to the database
            conn.commit()
            logging.debug("Changes committed to the database.")
            
            # Close the connection
            conn.close()
            logging.debug("Database connection closed.")

            return {"message": "Session ended successfully", "username": digimealusername}, 200
        else:
            logging.warning(f"User {digimealusername} not found.")
            return {"error": "User not found."}, 404

    except sqlite3.Error as e:
        logging.error(f"SQLite error occurred: {str(e)}")
        return {"error": f"Database error: {str(e)}"}, 500  
    except Exception as e:
        logging.error(f"Unexpected error occurred: {str(e)}")
        return {"error": f"An unexpected error occurred: {str(e)}"}, 500

# ✅ Fixed: Added missing commit
@app.route('/sesion_recover/<digimealusername>', methods=['GET'])
@token_required
def sesion_recover(digimealusername):
    current_date = datetime.date.today().strftime('%Y-%m-%d')  # Format the current date as 'YYYY-MM-DD'
    logging.info(f"Session recovery requested for user: {digimealusername}")
    logging.debug(f"Current date: {current_date}")

    try:
        # Connect to the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        logging.debug("Database connection established.")
        
        # Fetch the current 'sessiya' value from the database
        cursor.execute('SELECT sessiya FROM all_users WHERE digimealusername = ?', (digimealusername,))
        result = cursor.fetchone()

        if result:
            sessiya = result[0]  # Get the stringified JSON from the database
            logging.debug(f"Current sessiya: {sessiya}")
            
            # Parse the existing JSON
            try:
                sessiya_data = json.loads(sessiya)
                logging.debug(f"Parsed sessiya data: {sessiya_data}")
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON from sessiya: {e}")
                return {"error": "Error decoding JSON from sessiya"}, 500
            
            # Create a new entry for 'sessiya_baslama' with the current date
            new_key = f"sessiya_baslama_{current_date}"  # Create a unique key based on the date
            sessiya_data[new_key] = current_date  # Add the new entry with the date as the value
            
            logging.debug(f"Updated sessiya with new session start entry: {new_key} = {current_date}")
            
            # Stringify the updated JSON
            updated_sessiya = json.dumps(sessiya_data)
            logging.debug(f"Updated sessiya: {updated_sessiya}")
            
            # Update the 'sessiya' field in the database with the new JSON
            cursor.execute('''
                UPDATE all_users
                SET sessiya = ?, approved = ?
                WHERE digimealusername = ?
            ''', (updated_sessiya, 1, digimealusername))  # Update approved to 1 as well
            logging.debug(f"Updated sessiya and set approved = 1 for user {digimealusername} in all_users table.")
            
            # Update 'approved' field in 'users' table
            cursor.execute('UPDATE users SET approved = 1 WHERE digimealusername = ?', (digimealusername,))
            logging.debug(f"Set approved = 1 for user {digimealusername} in users table.")
            
            # Commit the changes to the database
            conn.commit()
            logging.debug("Changes committed to the database.")
            
            # Close the connection
            conn.close()
            logging.debug("Database connection closed.")

            return {"message": "Session recovered successfully", "username": digimealusername}, 200
        else:
            logging.warning(f"User {digimealusername} not found.")
            return {"error": "User not found."}, 404

    except sqlite3.Error as e:
        logging.error(f"SQLite error occurred: {str(e)}")
        return {"error": f"Database error: {str(e)}"}, 500  
    except Exception as e:
        logging.error(f"Unexpected error occurred: {str(e)}")
        return {"error": f"An unexpected error occurred: {str(e)}"}, 500


# super admin search
@app.route('/delete_user/<fin_kod>', methods=['DELETE'])
@token_required
def delete_user(fin_kod):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Execute delete query
        cursor.execute('DELETE FROM all_users WHERE fin_kod = ?', (fin_kod,))
        cursor.execute('DELETE FROM users WHERE fin_kod = ?', (fin_kod,))
        conn.commit()  

        if cursor.rowcount > 0:
            message = f"'{fin_kod}' fin kodlu istifadəçi müraciəti ləğv olundu."
            return {"message": message}, 200
        else:
            return {"message": f"No user found with FIN code '{fin_kod}'."}, 404
    except sqlite3.Error as e:
        return {"error": str(e)}, 500
    finally:
        conn.close()
        
# Route to generate QR code for user
@app.route('/user/generate_qr', methods=['POST'])
@token_required
def generate_qr():
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({"success": False, "message": "Username is required."}), 400

    today = str(date.today())
    print(today)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('SELECT id, image, date FROM qr_codes WHERE username = ? AND date = ?',
                   (username, today))
    existing_qr = cursor.fetchone()

    if existing_qr:
        return jsonify({
            "success": True,
            "id": existing_qr[0],
            "image": existing_qr[1],
            "date": existing_qr[2]
        })

    # Generate a new QR code with the correct ID
    qr_id = str(uuid.uuid4())  # Generate a unique ID
    qr_image = generate_qr_code(qr_id)  # Encode the ID, not the username
    cursor.execute('''INSERT INTO qr_codes (id, username, image, date, status) VALUES (?, ?, ?, ?, 1)''',
                   (qr_id, username, qr_image, today))
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "id": qr_id,  # Return the correct ID
        "image": qr_image,
        "date": today
    })


# Function to generate QR code image
def generate_qr_code(data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)  # Now encoding the ID instead of username
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode("utf-8")


# Route to get the username for a user
@app.route('/user/username', methods=['POST'])
@token_required
def get_username():
    digimealusername = request.current_user  

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT ad FROM users WHERE digimealusername = ?', (digimealusername,))
        result = cursor.fetchone()

        if result:
            istifadeci_adi = result[0]
            return jsonify({"success": True, "istifadeci_adi": istifadeci_adi}), 200
        else:
            return jsonify({"success": False, "message": "Username not found"}), 404
    except sqlite3.Error as e:
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()
        # Route to get user QR code history

@app.route('/user/settings/', methods=['GET'])
@token_required
def get_user_settings():
    digimealusername = request.current_user  # Get the username from the token
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT ad, soyad, status FROM users WHERE digimealusername = ?', (digimealusername,))
        user = cursor.fetchone()
        conn.close()

        if user:
            return jsonify({
                "ad": user[0],
                "soyad": user[1],
                "status": user[2]
            }), 200
        else:
            return jsonify({"error": "User not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/user/history/<username>', methods=['GET'])
@token_required
def history(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, date, status FROM qr_codes WHERE username = ?', (username,))
    rows = cursor.fetchall()
    conn.close()

    qr_data = [{"id": row[0], "date": row[1], "status": row[2]} for row in rows]
    return jsonify(qr_data), 200


# Route to get all QR codes for a user
@app.route('/user/get_qrs/<username>', methods=['GET'])
@token_required
def get_qrs(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, image, date, status FROM qr_codes WHERE username = ?', (username,))
    rows = cursor.fetchall()
    conn.close()

    qr_data = [{"id": row[0], "image": row[1], "date": row[2], "status": row[3]} for row in rows]
    return jsonify(qr_data), 200




#scanner


@app.route('/scanner/login', methods=['POST'])
def scanner_login():
    data = request.json
    scanner_username = data.get('username')
    scanner_password = data.get('password')
    if not scanner_username or not scanner_password:
        return jsonify({"success": False, "message": "Username and password required"}), 400
    result = check_scanner_login(scanner_username, scanner_password)
    return jsonify(result), 200 if result['success'] else 401


# Route to get scanner username and faculty
@app.route('/scanner/get_scanner_username', methods=['POST'])
@token_required
def get_scanner_username():
    data = request.json
    usernamesc = data.get('usernamesc')

    if not usernamesc:
        return jsonify({"success": False, "message": "Username is required"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT scanner_istifadeci_adi, faculty FROM scanner_identification WHERE scanner_username = ?', 
                       (usernamesc,))
        result = cursor.fetchall()

        results_for_sc = [{"istifadeciadi": row[0], "faculty": row[1]} for row in result]

        if results_for_sc:
            return jsonify({"success": True, "results": results_for_sc}), 200
        else:
            return jsonify({"success": False, "message": "Username not found"}), 404
    except sqlite3.Error as e:
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

@app.route('/scannerscan', methods=['POST'])
def update_status_in_db():
    conn = None
    try:
        data = request.get_json()
        qr_id = data.get("qr_id")
        bufet = data.get("bufet")

        if not qr_id or not bufet:
            return jsonify({"message": "QR ID and bufet are required"}), 400

        print(f"QR ID received: {qr_id}, Bufet received: {bufet}")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Check if the QR ID exists with status 1
        print(f"Executing query with QR ID: {qr_id}")
        cursor.execute("SELECT * FROM qr_codes WHERE id = ? AND status = 1", (qr_id,))
        result = cursor.fetchone()

        if result:
            # Update status to 0 and set bufet value if a match is found
            print(f"Found QR ID: {qr_id}, updating status and bufet.")
            cursor.execute("UPDATE qr_codes SET status = 0, bufet = ? WHERE id = ?", (bufet, qr_id))
            conn.commit()
            return jsonify({"message": f"QR Code {qr_id} status updated and bufet set to {bufet}."}), 200
        else:
            print(f"No matching QR ID {qr_id} with status 1 found.")
            return jsonify({"message": f"No matching QR ID {qr_id} with status 1 found."}), 404
    except sqlite3.Error as e:
        print(f"Error updating status in database: {e}")
        return jsonify({"message": "Database error occurred"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/get_bufet_account', methods=['GET'])
@token_required
def get_bufet_account():
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT date, qiymet, bufet FROM qr_codes WHERE status = 0 AND bufet IS NOT NULL")
        result = cursor.fetchall()

        if result:
            qr_codes = [{"date": row[0], "qiymet": row[1], "bufet": row[2]} for row in result]
            return jsonify({"success": True, "data": qr_codes}), 200
        else:
            return jsonify({"success": False, "message": "No data found"}), 404

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return jsonify({"success": False, "message": "Database error occurred"}), 500
    finally:
        if conn:
 
          conn.close()

@app.route('/get_last_5_qr_codes', methods=['GET'])
@token_required
def get_last_5_qr_codes_route():
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    query = "SELECT * FROM qr_codes ORDER BY date DESC LIMIT 5"
    
    cursor.execute(query)
    rows = cursor.fetchall()
    print(rows)
    
    result = []
    for row in rows:
        result.append({
            'username': row[1],  
            'date': row[3],      
            'status': row[4],    
            'qiymet': row[5],    
        })
    
    
    conn.close()
    
    
    return jsonify(result)

@app.route('/get_all_user_account', methods=['GET'])
@token_required
def get_all_user_account():
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT ad, soyad, ata_adi, fin_kod, fakulte, status, approved, digimealusername, document, qeydiyyat_tarixi, qeyd, telefon_nomresi, qrup_no, sessiya from all_users where approved = 1")
        result = cursor.fetchall()
        print(result)

        if result:
            qr_codes = [{
                "ad": row[0], 
                "soyad": row[1], 
                "ata_adi": row[2],
                "fin_kod": row[3],
                "fakulte": row[4],
                "status": row[5],
                "approved": row[6],
                "digimealusername": row[7],
                "document": row[8],
                "qeydiyyat_tarixi": row[9],
                "qeyd": row[10],
                "phonenumber": row[11],
                "qrup_no": row[12],
                "sessiya": row[13]
            } for row in result]
            return jsonify({"success": True, "data": qr_codes}), 200
        else:
            return jsonify({"success": False, "message": "No data found"}), 404

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return jsonify({"success": False, "message": "Database error occurred"}), 500
    finally:
        if conn:
 
          conn.close()

@app.route('/get_qr_code_by_username', methods=['GET'])
@token_required
def get_qr_code_by_username():
    username = request.args.get('username')
    month = request.args.get('month')
    year = request.args.get('year')
    
    if not username:
        return jsonify({"success": False, "message": "Username is required"}), 402
    
    if not month:
        return jsonify({"success": False, "message": "Month is required"}), 404
    if not month.isdigit() or not (1 <= int(month) <= 12):
        return jsonify({"success": False, "message": "Invalid month number. Please provide a valid month (1-12)."}), 403
    
      # Ensure this gets the current year
    date_condition = f"strftime('%Y', date) = ? AND strftime('%m', date) = ?"
    params = (str(year), f"{int(month):02d}")
    
    print(f"Executing query with parameters: {username}, {year}, {f'{int(month):02d}'}")
    
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        query = f"SELECT SUM(qiymet) FROM qr_codes WHERE username = ? AND status = 0 AND {date_condition}"
        cursor.execute(query, (username,) + params)
        result = cursor.fetchone()

        if result and result[0] is not None:
            total_qiymet = result[0]
            return jsonify({"success": True, "total_qiymet": total_qiymet}), 200
        else:
            print(f"No result found for query with username: {username}, month: {month}")
            return jsonify({"success": False, "message": "No QR code data found for the provided username and month"}), 404

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return jsonify({"success": False, "message": "Database error occurred"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/request-and-send-otp', methods=['POST'])
@token_required
def request_and_send_otp():
    data = request.get_json()
    receiver_email = data.get("email")
    print(receiver_email)
    
    if not receiver_email:
        return jsonify({"success": False, "message": "Email is required"}), 400

    otp = generate_otp()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    username = generate_username()
    try:
        cursor.execute("UPDATE users SET digimealusername = ? WHERE email = ?", (username, receiver_email))
        cursor.execute("UPDATE all_users SET otp = ?, digimealusername = ? WHERE email = ?", (otp, username, receiver_email))
        conn.commit()
    except sqlite3.Error as e:
        return jsonify({"success": False, "message": f"Database error: {e}"}), 500
    finally:
        conn.close()
    otp_sent = send_otp(receiver_email, username, otp)
    if otp_sent:
        return jsonify({"success": True, "message": "OTP sent successfully"}), 200
    else:
        return jsonify({"success": False, "message": "Failed to send OTP"}), 500
    

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
