from flask import Flask, render_template, request, redirect, url_for, jsonify, session
import json
import secrets
import os
import subprocess
import hmac
from functools import wraps
from datetime import datetime
import pymysql
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_COOKIE_SECURE", "").lower() == "true",
)
app.config["UPLOAD_FOLDER"] = os.environ.get(
    "UPLOAD_FOLDER",
    os.path.join(app.root_path, "uploads", "disabled_proofs"),
)

@app.errorhandler(500)
def handle_internal_error(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "The parking API returned an internal server error."}), 500
    return error


PARKING_STATUSES = {
    "available",
    "occupied",
    "reserved",
    "maintenance"
}

ALLOWED_PROOF_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}
ROLE_SESSION_KEYS = {
    "user": "user_id",
    "admin": "admin_mall_id",
    "staff": "staff_id",
}
ROLE_LOGIN_ENDPOINTS = {
    "user": "user_login",
    "admin": "admin_login",
    "staff": "mall_login",
}


def require_role(role):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            is_authenticated = (
                session.get("auth_role") == role
                and session.get(ROLE_SESSION_KEYS[role])
            )
            if not is_authenticated:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Authentication is required."}), 401
                return redirect(url_for(ROLE_LOGIN_ENDPOINTS[role]))
            return view(*args, **kwargs)

        return wrapped

    return decorator


def verify_password(password, stored_password):
    if not isinstance(stored_password, str):
        return False
    if stored_password.startswith(("scrypt:", "pbkdf2:")):
        try:
            return check_password_hash(stored_password, password)
        except ValueError:
            return False
    return hmac.compare_digest(stored_password, password)


def is_password_hashed(stored_password):
    return isinstance(stored_password, str) and stored_password.startswith(("scrypt:", "pbkdf2:"))


def upgrade_legacy_password(cursor, table_name, account_id, password):
    cursor.execute(
        f"UPDATE {table_name} SET password = %s WHERE id = %s",
        (generate_password_hash(password), account_id),
    )


def run_java_gate(vehicle_type, slot_type, slot_vehicle_type, supports_big_vehicles, start_time, end_time):
    java_file = os.path.join(app.root_path, "ParkingGateDecision.java")
    class_file = os.path.join(app.root_path, "ParkingGateDecision.class")

    if not os.path.exists(java_file):
        raise FileNotFoundError("Java gate component is missing.")

    if not os.path.exists(class_file) or os.path.getmtime(java_file) > os.path.getmtime(class_file):
        subprocess.run(["javac", java_file], cwd=app.root_path, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    result = subprocess.run(
        [
            "java",
            "-cp", app.root_path,
            "ParkingGateDecision",
            vehicle_type,
            slot_type,
            slot_vehicle_type,
            "true" if supports_big_vehicles else "false",
            start_time,
            end_time
        ],
        cwd=app.root_path,
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )

    payload = result.stdout.strip()
    if not payload:
        raise ValueError("Java gate returned no result.")

    data = json.loads(payload)
    return bool(data.get("allowed", False)), data.get("message", "Gate check failed."), float(data.get("price", 0.0))


def evaluate_parking_gate(vehicle_type, slot_type, slot_vehicle_type, supports_big_vehicles, start_time, end_time):
    return run_java_gate(vehicle_type, slot_type, slot_vehicle_type, supports_big_vehicles, start_time, end_time)


# =========================
# MYSQL DATABASE CONNECTION
# =========================

def get_db_connection():
    connection_options = {
        "host": "mysql-21f047be-arslogamithra-ded6.l.aivencloud.com",
        "port": 12429,
        "user": "avnadmin",
        "password": "AVNS_iOgqZAwxlbihn9ceFcE",
        "database": "defaultdb",
        "cursorclass": pymysql.cursors.DictCursor,
    }
    ssl_ca = os.environ.get("DB_SSL_CA")
    if ssl_ca:
        connection_options["ssl"] = {"ca": ssl_ca}
    return pymysql.connect(**connection_options)

# =========================
# HOME
# =========================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/about.html")
def about():
    return render_template("about.html")


# =========================
# MALL ROLE SELECTION
# =========================

@app.route("/mall.html")
@app.route("/mall")
def mall_role_selection():
    mall_id = request.args.get("id", type=int)

    if mall_id:
        return render_template("mall_parking.html", mall_id=mall_id)

    return render_template("mall.html")


# =========================
# USER LOGIN PAGE
# =========================

@app.route("/user-login")
def user_login():
    return render_template("user_login.html")


# =========================
# USER REGISTER PAGE
# =========================

@app.route("/user-register")
def user_register():
    return render_template("user_register.html")


# =========================
# USER REGISTRATION
# =========================

@app.route("/user/register", methods=["POST"])
def user_register_submit():

    name = request.form.get("name")
    email = request.form.get("email")
    phone = request.form.get("phone")
    password = request.form.get("password")
    confirm_password = request.form.get("confirmPassword")

    # Check password confirmation
    if password != confirm_password:
        return "Passwords do not match!"
    if len(password or "") < 8:
        return "Password must be at least 8 characters long.", 400

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:

            # Check whether email already exists
            cursor.execute(
                "SELECT * FROM users WHERE email = %s",
                (email,)
            )

            existing_user = cursor.fetchone()

            if existing_user:
                return "Email already registered!"

            # Insert new user
            cursor.execute(
                """
                INSERT INTO users (name, email, phone, password)
                VALUES (%s, %s, %s, %s)
                """,
                (name, email, phone, generate_password_hash(password))
            )

        connection.commit()

    finally:
        connection.close()

    # Registration successful → Login page
    return redirect(url_for("user_login"))


# =========================
# USER LOGIN
# =========================

@app.route("/user/login", methods=["POST"])
def user_login_submit():

    email = request.form.get("email")
    password = request.form.get("password")

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT * FROM users
                WHERE email = %s
                """,
                (email,)
            )

            user = cursor.fetchone()
            if user and verify_password(password or "", user["password"]):
                if not is_password_hashed(user["password"]):
                    upgrade_legacy_password(cursor, "users", user["id"], password)
                    connection.commit()
            else:
                user = None

    finally:
        connection.close()

    if user:
        session.clear()
        session["auth_role"] = "user"
        session["user_id"] = user["id"]
        return redirect(url_for("user_dashboard"))

    # Login failed
    return "Invalid email or password!"

@app.route("/user-dashboard")
@require_role("user")
def user_dashboard():
    return render_template("user_dashboard.html")


@app.route("/my-bookings.html")
@require_role("user")
def my_bookings():
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT malls.mall_name, parking_slots.slot_number,
                       DATE_FORMAT(parking_reservations.parking_date, '%%b %%d, %%Y') AS parking_date,
                       TIME_FORMAT(parking_reservations.start_time, '%%H:%%i') AS start_time,
                       TIME_FORMAT(parking_reservations.end_time, '%%H:%%i') AS end_time,
                       parking_reservations.vehicle_type,
                       parking_reservations.status
                FROM parking_reservations
                JOIN malls ON malls.id = parking_reservations.mall_id
                JOIN parking_slots ON parking_slots.id = parking_reservations.slot_id
                WHERE parking_reservations.user_id = %s
                ORDER BY parking_reservations.created_at DESC
                """,
                (session["user_id"],),
            )
            bookings = cursor.fetchall()
    finally:
        connection.close()

    return render_template("my_bookings.html", bookings=bookings)


@app.route("/user/current")
@require_role("user")
def current_user():
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT name, email, phone FROM users WHERE id = %s",
                (session["user_id"],),
            )
            user = cursor.fetchone()
    finally:
        connection.close()

    if not user:
        session.clear()
        return jsonify({"error": "User account not found."}), 404
    return jsonify(user)


@app.route("/api/malls/<int:mall_id>/slots", methods=["GET"])
def get_mall_slots(mall_id):

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT mall_name FROM malls WHERE id = %s",
                (mall_id,)
            )
            mall = cursor.fetchone()

            cursor.execute(
                """
                SELECT id, slot_number, status, slot_type, vehicle_type, supports_big_vehicles
                FROM parking_slots
                WHERE mall_id = %s
                ORDER BY slot_number
                """,
                (mall_id,)
            )
            slots = cursor.fetchall()

    finally:
        connection.close()

    if not mall:
        return jsonify({"error": "Mall not found."}), 404

    return jsonify({"mall": mall, "slots": slots})


@app.route("/api/reservations", methods=["POST"])
@require_role("user")
def create_reservation():

    data = request.get_json(silent=True) or request.form
    mall_id = data.get("mallId")
    slot_id = data.get("slotId")
    user_name = (data.get("name") or "").strip()
    user_email = (data.get("email") or "").strip()
    user_phone = (data.get("phone") or "").strip()
    vehicle_type = (data.get("vehicleType") or "").strip()
    parking_date = (data.get("parkingDate") or "").strip()
    start_time = (data.get("startTime") or "").strip()
    end_time = (data.get("endTime") or "").strip()

    if not all([mall_id, slot_id, user_name, user_email, user_phone, vehicle_type, parking_date, start_time, end_time]):
        return jsonify({"error": "All booking details are required."}), 400

    if vehicle_type not in {"two_wheeler", "four_wheeler", "truck"}:
        return jsonify({"error": "Choose a valid vehicle type."}), 400

    try:
        parking_start_value = datetime.strptime(f"{parking_date} {start_time}", "%Y-%m-%d %H:%M")
        parking_end_value = datetime.strptime(f"{parking_date} {end_time}", "%Y-%m-%d %H:%M")
        parking_start = parking_start_value.strftime("%Y-%m-%d %H:%M:%S")
        parking_end = parking_end_value.strftime("%Y-%m-%d %H:%M:%S")
        if parking_end <= parking_start:
            raise ValueError
    except ValueError:
        return jsonify({"error": "Choose a valid parking time period."}), 400

    try:
        mall_id = int(mall_id)
        slot_id = int(slot_id)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid mall or slot."}), 400

    qr_token = secrets.token_urlsafe(32)
    connection = get_db_connection()
    proof_file = request.files.get("disabledProof")

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT slot_type, vehicle_type, supports_big_vehicles
                FROM parking_slots
                WHERE id = %s AND mall_id = %s AND status = 'available'
                """,
                (slot_id, mall_id)
            )
            slot = cursor.fetchone()

            if not slot:
                return jsonify({"error": "That parking slot is no longer available."}), 409

            slot_vehicle_type = slot.get("vehicle_type", "all")
            supports_big_vehicles = bool(slot.get("supports_big_vehicles"))
            gate_approved, gate_message, price = evaluate_parking_gate(
                vehicle_type,
                slot["slot_type"],
                slot_vehicle_type,
                supports_big_vehicles,
                start_time,
                end_time,
            )
            if not gate_approved:
                return jsonify({"error": gate_message, "price": 0.0}), 400

            proof_filename = None
            if slot["slot_type"] == "disabled":
                if not proof_file or not proof_file.filename:
                    return jsonify({"error": "Proof is required to reserve a disabled slot."}), 400
                extension = proof_file.filename.rsplit(".", 1)[-1].lower() if "." in proof_file.filename else ""
                if extension not in ALLOWED_PROOF_EXTENSIONS:
                    return jsonify({"error": "Proof must be a PDF, JPG, JPEG, or PNG file."}), 400
                proof_filename = f"{secrets.token_hex(16)}_{secure_filename(proof_file.filename)}"

            cursor.execute(
                """
                UPDATE parking_slots
                SET status = 'reserved', vehicle_number = NULL
                WHERE id = %s AND mall_id = %s AND status = 'available'
                """,
                (slot_id, mall_id)
            )

            if cursor.rowcount != 1:
                connection.rollback()
                return jsonify({"error": "That parking slot is no longer available."}), 409

            cursor.execute(
                """
                INSERT INTO parking_reservations
                    (mall_id, slot_id, user_id, user_name, user_email, user_phone,
                     vehicle_type, parking_date, start_time, end_time, disabled_proof,
                     qr_token, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'reserved')
                """,
                (
                    mall_id,
                    slot_id,
                    session.get("user_id"),
                    user_name,
                    user_email,
                    user_phone,
                    vehicle_type,
                    parking_date,
                    start_time,
                    end_time,
                    proof_filename,
                    qr_token
                )
            )

        connection.commit()

    finally:
        connection.close()

    if proof_file and proof_filename:
        proof_directory = app.config["UPLOAD_FOLDER"]
        os.makedirs(proof_directory, exist_ok=True)
        proof_file.save(os.path.join(proof_directory, proof_filename))

    gate_approved, gate_message, price = evaluate_parking_gate(
        vehicle_type,
        slot["slot_type"],
        slot.get("vehicle_type", "all"),
        bool(slot.get("supports_big_vehicles")),
        start_time,
        end_time,
    )
    return jsonify({
        "message": "Reservation successful.",
        "qrToken": qr_token,
        "gateMessage": gate_message,
        "price": price
    }), 201


@app.route("/api/security/scan", methods=["POST"])
@require_role("staff")
def scan_reservation_qr():

    data = request.get_json(silent=True) or request.form
    qr_token = data.get("qrToken")
    staff_mall_id = session.get("staff_mall_id")

    if not staff_mall_id:
        return jsonify({"error": "Staff login is required to scan QR codes."}), 401

    if not qr_token:
        return jsonify({"error": "QR token is required."}), 400

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, slot_id FROM parking_reservations
                WHERE qr_token = %s AND mall_id = %s AND status = 'reserved'
                """,
                (qr_token, staff_mall_id)
            )
            reservation = cursor.fetchone()

            if not reservation:
                return jsonify({"error": "Invalid or already used QR code."}), 409

            cursor.execute(
                """
                UPDATE parking_reservations
                SET status = 'occupied', scanned_at = CURRENT_TIMESTAMP
                WHERE id = %s AND status = 'reserved'
                """,
                (reservation["id"],)
            )
            cursor.execute(
                """
                UPDATE parking_slots
                SET status = 'occupied'
                WHERE id = %s AND mall_id = %s AND status = 'reserved'
                """,
                (reservation["slot_id"], staff_mall_id)
            )

        connection.commit()

    finally:
        connection.close()

    return jsonify({"message": "QR accepted. Parking slot is now occupied."})

# =========================
# STAFF LOGIN PAGE
# =========================

@app.route("/mall-login")
def mall_login():
    return render_template("mall_login.html")


# =========================
# ADMIN LOGIN PAGE
# =========================

@app.route("/admin-login")
def admin_login():
    return render_template("admin_login.html")


@app.route("/admin/login", methods=["POST"])
def admin_login_submit():

    email = request.form.get("email")
    password = request.form.get("password")

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT id, password FROM malls
                WHERE email = %s
                """,
                (email,)
            )

            mall_admin = cursor.fetchone()
            if mall_admin and verify_password(password or "", mall_admin["password"]):
                if not is_password_hashed(mall_admin["password"]):
                    upgrade_legacy_password(cursor, "malls", mall_admin["id"], password)
                    connection.commit()
            else:
                mall_admin = None

    finally:
        connection.close()

    if mall_admin:
        session.clear()
        session["auth_role"] = "admin"
        session["admin_mall_id"] = mall_admin["id"]
        return redirect(url_for("admin_dashboard"))

    return "Invalid admin email or password.", 401


# =========================
# MALL REGISTRATION PAGE
# =========================

@app.route("/mall-register")
def mall_register():
    return render_template("mall_register.html")


# =========================
# MALL REGISTRATION
# =========================

@app.route("/mall/register", methods=["POST"])
def mall_register_submit():

    mall_name = request.form.get("mallName")
    address = request.form.get("address")
    phone = request.form.get("phone")
    email = request.form.get("email")
    password = request.form.get("password")
    confirm_password = request.form.get("confirmPassword")
    registration_code = request.form.get("registrationCode")

    if not all([
        mall_name,
        address,
        phone,
        email,
        password,
        confirm_password,
        registration_code
    ]):
        return "All fields are required.", 400

    if password != confirm_password:
        return "Passwords do not match.", 400
    if len(password or "") < 8:
        return "Password must be at least 8 characters long.", 400

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT id FROM malls
                WHERE mall_name = %s OR registration_code = %s
                """,
                (mall_name, registration_code)
            )

            if cursor.fetchone():
                return "Mall name or registration code is already registered.", 409

            cursor.execute(
                """
                INSERT INTO malls
                    (mall_name, address, phone, email, password, registration_code)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    mall_name,
                    address,
                    phone,
                    email,
                    generate_password_hash(password),
                    registration_code
                )
            )

        connection.commit()

    finally:
        connection.close()

    return redirect(url_for("mall_login"))


# =========================
# STAFF REGISTRATION PAGE
# =========================

@app.route("/staff-register")
def staff_register():
    return render_template("staff_register.html")


# =========================
# GET ALL REGISTERED MALLS
# =========================

@app.route("/api/malls", methods=["GET"])
def get_malls():

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:

            cursor.execute("""
                SELECT
                    malls.id,
                    malls.mall_name AS mallName,
                    malls.address,
                    malls.phone,
                    COUNT(parking_slots.id) AS totalSlots,
                    CAST(COALESCE(SUM(parking_slots.status = 'available'), 0) AS UNSIGNED) AS availableSlots
                FROM malls
                LEFT JOIN parking_slots ON parking_slots.mall_id = malls.id
                GROUP BY malls.id, malls.mall_name, malls.address, malls.phone
                ORDER BY mall_name
            """)

            malls = cursor.fetchall()

            return jsonify(malls)

    finally:
        connection.close()


# =========================
# STAFF REGISTRATION
# =========================

@app.route("/api/staffs/register", methods=["POST"])
def staff_register_submit():

    data = request.get_json(silent=True) or request.form

    mall_id = data.get("mallId")
    name = data.get("name")
    email = data.get("email")
    phone = data.get("phone")
    login_id = data.get("loginId")
    password = data.get("password")
    confirm_password = data.get("confirmPassword")
    registration_code = data.get("registrationCode")

    if not all([
        mall_id,
        name,
        email,
        phone,
        login_id,
        password,
        registration_code
    ]):
        return "All fields are required.", 400

    if password != confirm_password:
        return "Passwords do not match.", 400
    if len(password or "") < 8:
        return "Password must be at least 8 characters long.", 400

    try:
        mall_id = int(mall_id)
    except (TypeError, ValueError):
        return "Invalid mall.", 400

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT id FROM malls
                WHERE id = %s AND registration_code = %s
                """,
                (mall_id, registration_code)
            )

            if not cursor.fetchone():
                return "Selected mall does not exist.", 400

            cursor.execute(
                """
                SELECT id FROM staffs
                WHERE email = %s OR login_id = %s
                """,
                (email, login_id)
            )

            if cursor.fetchone():
                return "Email or login ID is already registered.", 409

            cursor.execute(
                """
                INSERT INTO staffs
                    (mall_id, name, email, phone, login_id, password)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (mall_id, name, email, phone, login_id, generate_password_hash(password))
            )

        connection.commit()

    finally:
        connection.close()

    return "Staff registered successfully.", 201


# =========================
# STAFF LOGIN
# =========================

@app.route("/staff/login", methods=["POST"])
def staff_login_submit():

    mall_name = request.form.get("mallName")
    login_id = request.form.get("loginId")
    password = request.form.get("password")

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:

            cursor.execute("""
                SELECT staffs.*
                FROM staffs
                JOIN malls ON malls.id = staffs.mall_id
                WHERE malls.mall_name = %s
                AND staffs.login_id = %s
            """, (mall_name, login_id))

            staff = cursor.fetchone()

            if staff and verify_password(password or "", staff["password"]):
                if not is_password_hashed(staff["password"]):
                    upgrade_legacy_password(cursor, "staffs", staff["id"], password)
                    connection.commit()
                session.clear()
                session["auth_role"] = "staff"
                session["staff_id"] = staff["id"]
                session["staff_mall_id"] = staff["mall_id"]
                return redirect(url_for("staff_dashboard"))

            return "Invalid Mall, Staff ID or Password.", 401

    finally:
        connection.close()


# =========================
# ADMIN DASHBOARD
# =========================

@app.route("/mall-dashboard")
def mall_dashboard():
    return redirect(url_for("admin_dashboard"))


@app.route("/admin-dashboard")
@require_role("admin")
def admin_dashboard():

    mall_id = session.get("admin_mall_id")

    if not mall_id:
        return redirect(url_for("admin_login"))

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT mall_name, registration_code FROM malls WHERE id = %s",
                (mall_id,)
            )
            mall = cursor.fetchone()

            cursor.execute(
                """
                SELECT id, name, email, phone, login_id
                FROM staffs
                WHERE mall_id = %s
                ORDER BY name
                """,
                (mall_id,)
            )
            staff_members = cursor.fetchall()

            cursor.execute(
                """
                SELECT id, slot_number, slot_type, vehicle_type,
                       supports_big_vehicles, status, vehicle_number
                FROM parking_slots
                WHERE mall_id = %s
                ORDER BY slot_number
                """,
                (mall_id,),
            )
            parking_slots = cursor.fetchall()

    finally:
        connection.close()

    if not mall:
        session.clear()
        return redirect(url_for("admin_login"))

    return render_template(
        "admin_dashboard.html",
        mall=mall,
        staff_members=staff_members,
        parking_slots=parking_slots,
    )


@app.route("/admin/staff-registration-code", methods=["POST"])
@require_role("admin")
def update_staff_registration_code():
    mall_id = session.get("admin_mall_id")
    registration_code = request.form.get("registrationCode", "").strip()

    if not mall_id:
        return redirect(url_for("admin_login"))

    if not registration_code:
        return "Staff registration code is required.", 400

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM malls WHERE id = %s",
                (mall_id,),
            )
            if not cursor.fetchone():
                session.clear()
                return redirect(url_for("admin_login"))

            cursor.execute(
                """
                SELECT id FROM malls
                WHERE registration_code = %s AND id != %s
                """,
                (registration_code, mall_id),
            )
            if cursor.fetchone():
                return "That staff registration code is already in use.", 409

            cursor.execute(
                "UPDATE malls SET registration_code = %s WHERE id = %s",
                (registration_code, mall_id),
            )

        connection.commit()

    except pymysql.err.IntegrityError:
        return "That staff registration code is already in use.", 409

    finally:
        connection.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/add-parking-slot")
@require_role("admin")
def add_parking_slot_page():
    mall_id = session.get("admin_mall_id")
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT mall_name FROM malls WHERE id = %s",
                (mall_id,),
            )
            mall = cursor.fetchone()
            cursor.execute(
                """
                SELECT id, slot_number, slot_type, vehicle_type,
                       supports_big_vehicles, status
                FROM parking_slots
                WHERE mall_id = %s
                ORDER BY slot_number
                """,
                (mall_id,),
            )
            parking_slots = cursor.fetchall()
    finally:
        connection.close()

    if not mall:
        session.clear()
        return redirect(url_for("admin_login"))

    return render_template(
        "admin_add_slot.html",
        mall=mall,
        parking_slots=parking_slots,
    )


@app.route("/admin/staff/<int:staff_id>/delete", methods=["POST"])
@require_role("admin")
def delete_staff(staff_id):

    mall_id = session.get("admin_mall_id")

    if not mall_id:
        return redirect(url_for("admin_login"))

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM staffs
                WHERE id = %s AND mall_id = %s
                """,
                (staff_id, mall_id)
            )

        connection.commit()

    finally:
        connection.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/parking-slots", methods=["POST"])
@require_role("admin")
def add_parking_slot():

    mall_id = session.get("admin_mall_id")
    slot_number = request.form.get("slotNumber", "").strip()
    slot_type = request.form.get("slotType", "normal")
    slot_vehicle_type = request.form.get("slotVehicleType", "all")
    supports_big_vehicles = request.form.get("supportsBigVehicles") == "on"

    if not mall_id:
        return redirect(url_for("admin_login"))

    if not slot_number:
        return "Slot number is required.", 400

    if slot_type not in {"normal", "disabled"}:
        return "Invalid slot type.", 400

    if slot_vehicle_type not in {"two_wheeler", "four_wheeler", "all"}:
        return "Invalid vehicle type for this slot.", 400

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO parking_slots (mall_id, slot_number, slot_type, vehicle_type, supports_big_vehicles, status)
                VALUES (%s, %s, %s, %s, %s, 'available')
                """,
                (mall_id, slot_number, slot_type, slot_vehicle_type, supports_big_vehicles)
            )

        connection.commit()

    except pymysql.err.IntegrityError:
        return "That slot already exists for this mall.", 409

    finally:
        connection.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/parking-slots/<int:slot_id>/delete", methods=["POST"])
@require_role("admin")
def delete_parking_slot(slot_id):

    mall_id = session.get("admin_mall_id")

    if not mall_id:
        return redirect(url_for("admin_login"))

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM parking_slots
                WHERE id = %s AND mall_id = %s
                """,
                (slot_id, mall_id)
            )

        connection.commit()

    finally:
        connection.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/parking-slots/<int:slot_id>", methods=["POST"])
@require_role("admin")
def update_admin_parking_slot(slot_id):

    mall_id = session.get("admin_mall_id")
    status = request.form.get("status")

    if not mall_id:
        return redirect(url_for("admin_login"))

    status_map = {
        "available": "available",
        "reserved": "reserved",
        "occupied": "occupied",
        "unavailable": "maintenance"
    }

    if status not in status_map:
        return "Invalid parking slot status.", 400

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE parking_slots
                SET status = %s,
                    vehicle_number = CASE
                        WHEN %s = 'available' OR %s = 'unavailable'
                        THEN NULL
                        ELSE vehicle_number
                    END
                WHERE id = %s AND mall_id = %s
                """,
                (status_map[status], status, status, slot_id, mall_id)
            )

        connection.commit()

    finally:
        connection.close()

    return redirect(url_for("admin_dashboard"))


# =========================
# STAFF DASHBOARD
# =========================

@app.route("/staff-dashboard")
@require_role("staff")
def staff_dashboard():

    staff_id = session.get("staff_id")
    mall_id = session.get("staff_mall_id")

    if not staff_id or not mall_id:
        return redirect(url_for("mall_login"))

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT staffs.name, staffs.login_id, malls.mall_name
                FROM staffs
                JOIN malls ON malls.id = staffs.mall_id
                WHERE staffs.id = %s AND staffs.mall_id = %s
                """,
                (staff_id, mall_id)
            )
            staff = cursor.fetchone()

            cursor.execute(
                """
                SELECT id, slot_number, slot_type, supports_big_vehicles, status, vehicle_number
                FROM parking_slots
                WHERE mall_id = %s
                ORDER BY slot_number
                """,
                (mall_id,)
            )
            parking_slots = cursor.fetchall()

    finally:
        connection.close()

    if not staff:
        session.clear()
        return redirect(url_for("mall_login"))

    slot_stats = {
        "total": len(parking_slots),
        "available": sum(slot["status"] == "available" for slot in parking_slots),
        "occupied": sum(slot["status"] == "occupied" for slot in parking_slots),
        "reserved": sum(slot["status"] == "reserved" for slot in parking_slots),
        "disabled": sum(slot["slot_type"] == "disabled" for slot in parking_slots),
        "big_vehicle": sum(bool(slot["supports_big_vehicles"]) for slot in parking_slots),
    }

    return render_template(
        "staff_dashboard.html",
        staff=staff,
        parking_slots=parking_slots,
        slot_stats=slot_stats
    )


@app.route("/staff-scan")
@require_role("staff")
def staff_scan():

    staff_id = session.get("staff_id")
    mall_id = session.get("staff_mall_id")

    if not staff_id or not mall_id:
        return redirect(url_for("mall_login"))

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT staffs.name, staffs.login_id, malls.mall_name
                FROM staffs
                JOIN malls ON malls.id = staffs.mall_id
                WHERE staffs.id = %s AND staffs.mall_id = %s
                """,
                (staff_id, mall_id)
            )
            staff = cursor.fetchone()

    finally:
        connection.close()

    if not staff:
        session.clear()
        return redirect(url_for("mall_login"))

    return render_template("staff_scan.html", staff=staff)


@app.route("/staff/parking-slots/<int:slot_id>", methods=["POST"])
@require_role("staff")
def update_parking_slot(slot_id):

    mall_id = session.get("staff_mall_id")
    status = request.form.get("status")
    vehicle_number = request.form.get("vehicleNumber", "").strip() or None

    if not mall_id:
        return redirect(url_for("mall_login"))

    if status not in PARKING_STATUSES:
        return "Invalid parking slot status.", 400

    if status == "available":
        vehicle_number = None

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE parking_slots
                SET status = %s, vehicle_number = %s
                WHERE id = %s AND mall_id = %s
                """,
                (status, vehicle_number, slot_id, mall_id)
            )

        connection.commit()

    finally:
        connection.close()

    return redirect(url_for("staff_dashboard"))



# =========================
# LOGOUT
# =========================

@app.route("/user/logout")
def logout():
    session.clear()
    return redirect(url_for("user_login"))


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/staff/logout")
def staff_logout():
    session.clear()
    return redirect(url_for("mall_login"))

# =========================
# RUN APPLICATION
# =========================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "").lower() == "true",
    )
