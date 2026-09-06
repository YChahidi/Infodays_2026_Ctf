from flask import Flask, request, send_file, render_template, redirect, url_for, flash, jsonify, make_response
import tempfile
import os
import shutil
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from ics import Calendar, Event
from middleware.verification import verify_token
from middleware.pow_gate import verify_with_window as pow_verify, POW_BITS, BUCKET_SECONDS
from config import signature
import pymysql.cursors
from pymysql.constants import CLIENT
import jwt
import secrets
import hashlib

app = Flask(__name__, static_url_path='/static')
temp_dir = ''
app.secret_key = secrets.token_hex(32)

db_config = {
    'host': '127.0.0.1',
    'user': 'yuno',
    'password': '3wDo7gSRZIwIHRxZ!',
    'database': 'mana_db',
    'cursorclass': pymysql.cursors.DictCursor,
    'client_flag': CLIENT.MULTI_STATEMENTS,
    'unix_socket': '/var/run/mysqld/mysqld.sock',
}

access_token = ''


@app.route('/login', methods=['GET', 'POST'])
def login():
    global access_token
    if request.method == 'GET':
        resp = make_response(render_template('login.html', message=None))
        # Advertise the PoW requirement so honest clients know what to do.
        resp.headers['X-PoW-Bits'] = str(POW_BITS)
        resp.headers['X-PoW-Bucket-Seconds'] = str(BUCKET_SECONDS)
        resp.headers['X-PoW-Scheme'] = 'sha256(email:bucket:nonce)'
        return resp
    elif request.method == 'POST':
        email = request.json.get('email')
        password = request.json.get('password')
        # PoW gate (#7 anti-automation).  Stateless: sha256(email + ':' +
        # current 5-min UTC bucket + ':' + nonce) must have >= POW_BITS
        # leading zero bits.  The challenge mechanic is documented in the
        # X-PoW-Hint response header on GET /login.
        nonce = request.headers.get('X-PoW-Nonce', '')
        if not pow_verify(email or '', nonce):
            return jsonify(message="proof-of-work invalid or missing",
                           hint=f"X-PoW-Nonce: hex(sha256(email:bucket:nonce)) "
                                f"must start with {POW_BITS} zero bits, "
                                f"bucket=int(time/{BUCKET_SECONDS})"), 429
        password2 = hashlib.sha256(password.encode()).hexdigest()
        if not email or not password:
            return jsonify(message="email or password is missing"), 400

        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "SELECT * FROM users WHERE email=%s AND password=%s"
                cursor.execute(sql, (email, password2))
                user = cursor.fetchone()
                if user:
                    payload = {
                        'email': email,
                        'role': user['role_id'],
                        'iat': datetime.now(timezone.utc),
                        'exp': datetime.now(timezone.utc) + timedelta(seconds=3600),
                        'jwk': {'kty': 'RSA', "n": str(signature.n), "e": signature.e}
                    }
                    access_token = jwt.encode(payload, signature.key.export_key(), algorithm='RS256')
                    response = make_response(jsonify(access_token=access_token), 200)
                    response.set_cookie('X-AUTH-Token', access_token)
                    return response
                else:
                    return jsonify(message="Invalid email or password"), 401
        finally:
            connection.close()


@app.route('/logout', methods=['GET'])
def logout():
    response = make_response(redirect('/login'))
    response.set_cookie('X-AUTH-Token', '')
    return response


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html', message=None)
    elif request.method == 'POST':
        role_id = 'knight_' + secrets.token_hex(4)
        email = request.json.get('email')
        password = hashlib.sha256(request.json.get('password').encode()).hexdigest()
        if not email or not password:
            return jsonify(error="email or password is missing"), 400
        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "SELECT * FROM users WHERE email=%s"
                cursor.execute(sql, (email,))
                existing_user = cursor.fetchone()
                if existing_user:
                    return jsonify(error="Email already exists"), 400
                else:
                    sql = "INSERT INTO users (email, password, role_id) VALUES (%s, %s, %s)"
                    cursor.execute(sql, (email, password, role_id))
                    connection.commit()
                    return jsonify(message="User registered successfully"), 201
        finally:
            connection.close()


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@app.route('/book', methods=['GET', 'POST'])
def export():
    if request.method == 'POST':
        try:
            name = request.form['name']
            date = request.form['date']
            time = request.form['time']
            email = request.form['email']
            num_people = request.form['people']
            message = request.form['message']

            connection = pymysql.connect(**db_config)
            try:
                with connection.cursor() as cursor:
                    sql = "INSERT INTO appointments (appointment_name, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message, role_id) VALUES (%s, %s, %s, %s, %s, %s, %s)"
                    cursor.execute(sql, (name, email, date, time, num_people, message, 'knight'))
                    connection.commit()
                    flash('Your mana session request was sent. You can manage it from your dashboard. Thank you!', 'success')
            except Exception as e:
                print(e)
            return redirect('/#book-a-table')
        except ValueError:
            flash('Error processing your request. Please try again.', 'error')
    return render_template('index.html')


def generate_ics_file(name, date, time, email, num_people, message):
    global temp_dir
    temp_dir = tempfile.mkdtemp()
    current_date_time = datetime.now()
    formatted_date_time = current_date_time.strftime("%Y%m%d_%H%M%S")

    cal = Calendar()
    event = Event()

    event.name = name
    event.begin = datetime.strptime(str(date), "%Y-%m-%d")
    event.description = f"Email: {email}\nNumber of People: {num_people}\nMessage: {message}"

    cal.events.add(event)

    temp_file_path = os.path.join(temp_dir, quote('BlackBulls_mana_session_' + formatted_date_time + '.ics'))
    with open(temp_file_path, 'w') as fp:
        fp.write(cal.serialize())

    return os.path.basename(temp_file_path)


@app.route('/export/<path:filename>')
def export_file(filename):
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))
    filepath = os.path.join(temp_dir, filename)
    if os.path.exists(filepath):
        content = send_file(filepath, as_attachment=True)
        shutil.rmtree(temp_dir)
        return content
    else:
        shutil.rmtree(temp_dir)
        return "File not found", 404


def validate_login():
    try:
        (email, current_role), status_code = verify_token()
        if email and status_code == 200 and current_role == "captain":
            return current_role
        elif email and status_code == 200:
            return email
        else:
            raise Exception("Invalid token")
    except Exception:
        return None


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))
    elif validation == "captain":
        return redirect(url_for('captaindashboard'))

    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            sql = "SELECT appointment_id, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message FROM appointments WHERE appointment_email = %s"
            cursor.execute(sql, (validation,))
            connection.commit()
            appointments = cursor.fetchall()
            appointments_sorted = sorted(appointments, key=lambda x: x['appointment_id'])
    finally:
        connection.close()

    return render_template('dashboard.html', appointments=appointments_sorted)


@app.route('/delete/<appointID>')
def delete_file(appointID):
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))
    elif validation == "captain":
        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "DELETE FROM appointments where appointment_id= %s;"
                cursor.execute(sql, (appointID,))
                connection.commit()
        finally:
            connection.close()
            flash("Session deleted successfully", "success")
            return redirect(url_for("captaindashboard"))
    else:
        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "DELETE FROM appointments WHERE appointment_id = %s AND appointment_email = %s;"
                cursor.execute(sql, (appointID, validation))
                connection.commit()
        finally:
            connection.close()
            flash("Session deleted successfully", "success")
            return redirect(url_for("dashboard"))


@app.route('/reminder/<appointID>')
def reminder_file(appointID):
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))

    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            sql = "SELECT appointment_id, appointment_name, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message FROM appointments WHERE appointment_email = %s AND appointment_id = %s"
            result = cursor.execute(sql, (validation, appointID))
            if result != 0:
                connection.commit()
                appointments = cursor.fetchone()
                filename = generate_ics_file(appointments['appointment_name'], appointments['appointment_date'], appointments['appointment_time'], appointments['appointment_email'], appointments['appointment_people'], appointments['appointment_message'])
                connection.close()
                flash("Session reminder downloaded successfully", "success")
                return redirect(url_for('export_file', filename=filename))
            else:
                flash("Something went wrong!", "error")
    except Exception as _e:
        import traceback
        traceback.print_exc()
        flash("Something went wrong!", "error")

    return redirect(url_for("dashboard"))


@app.route('/captaindashboard', methods=['GET', 'POST'])
def captaindashboard():
    validation = validate_login()
    if validation != "captain":
        return redirect(url_for('login'))

    try:
        connection = pymysql.connect(**db_config)
        with connection.cursor() as cursor:
            sql = "SELECT * from appointments"
            cursor.execute(sql)
            connection.commit()
            appointments = cursor.fetchall()

            search_query = request.args.get('s', '')
            # Captain Yami added option to order the sessions
            order_query = request.args.get('o', '')

            sql = f"SELECT * FROM appointments WHERE appointment_email LIKE %s order by appointment_date {order_query}"
            cursor.execute(sql, ('%' + search_query + '%',))
            connection.commit()
            appointments = cursor.fetchall()
        connection.close()

        return render_template('captaindashboard.html', appointments=appointments)
    except Exception as e:
        flash(str(e), 'error')
        return render_template('captaindashboard.html', appointments=[])


if __name__ == '__main__':
    app.run(threaded=True, debug=False, host='0.0.0.0', port=8080)
