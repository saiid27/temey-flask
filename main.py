# -*- coding: utf-8 -*-
import os, random, time, sys
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
import mysql.connector
from mysql.connector.errors import IntegrityError

# ===== Sortie console UTF-8 (Windows) =====
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# ===== Flask =====
BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE, "templates"),
             static_folder=os.path.join(BASE, "static"))
app.secret_key = "change-this-secret"
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

# Dossiers d’upload
UP = os.path.join(BASE, "static", "uploads")
PAY_DIR = os.path.join(UP, "payments")
VID_DIR = os.path.join(UP, "videos")
PDF_DIR = os.path.join(UP, "pdfs")
for p in (PAY_DIR, VID_DIR, PDF_DIR):
    os.makedirs(p, exist_ok=True)

IMG_EXT   = {"jpg","jpeg","png","webp","pdf"}
VIDEO_EXT = {"mp4","webm","mkv","avi","mov","ogg"}
PDF_EXT   = {"pdf"}
def allowed(fn, exts): return "." in fn and fn.rsplit(".",1)[1].lower() in exts

# ===== MySQL =====
# قراءة المتغيرات البيئية من Vercel أو من إعدادات InfinityFree
DB_HOST = os.environ.get('DATABASE_HOST', 'sql302.infinityfree.com')  # استبدل `sqlXXX` بالعنوان الصحيح
DB_USER = os.environ.get('DATABASE_USER', 'if0_39807083')  # اسم المستخدم الذي حصلت عليه من InfinityFree
DB_PASSWORD = os.environ.get('DATABASE_PASSWORD', '27073327')  # كلمة المرور
DB_NAME = os.environ.get('DATABASE_NAME', 'if0_39807083_tem')  # اسم قاعدة البيانات

# الاتصال بقاعدة البيانات
def db():
    try:
        return mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None

# ===== SMS (Twilio ou mode DEV) =====
TWILIO_SID   = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_FROM  = os.getenv("TWILIO_FROM_NUMBER")
DEV_SMS      = not (TWILIO_SID and TWILIO_TOKEN and TWILIO_FROM)

def send_sms(phone: str, message: str):
    """
    En DEV on imprime une version ASCII-safe (pas d'accents) pour éviter UnicodeEncodeError,
    et on affiche le texte FR via flash.
    """
    if DEV_SMS:
        import re
        m = re.search(r"(\d{4,6})", message)
        code = m.group(1) if m else "xxxxxx"
        print(f"[DEV SMS] to {phone}: code={code}")  # ASCII only
        try:
            flash(f"(DEV) Code envoyé au {phone} : {code}", "secondary")
        except Exception:
            pass
        return True
    try:
        from twilio.rest import Client
        Client(TWILIO_SID, TWILIO_TOKEN).messages.create(to=phone, from_=TWILIO_FROM, body=message)
        return True
    except Exception as e:
        print("SMS error:", e)
        flash("Échec d’envoi du SMS. Vérifiez la configuration Twilio.", "danger")
        return False

# ===== OTP =====
def create_otp(phone: str, purpose: str) -> str:
    code = f"{random.randint(100000, 999999)}"
    expires_at = (datetime.utcnow() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""INSERT INTO verification_codes (phone, code, purpose, expires_at)
                       VALUES (%s,%s,%s,%s)""", (phone, code, purpose, expires_at))
        conn.commit(); cur.close()
    return code

def verify_otp(phone: str, purpose: str, code: str) -> bool:
    with db() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""SELECT id FROM verification_codes
                       WHERE phone=%s AND purpose=%s AND code=%s
                         AND used=0 AND expires_at>UTC_TIMESTAMP()
                       ORDER BY id DESC LIMIT 1""", (phone, purpose, code))
        row = cur.fetchone()
        if not row:
            cur.close(); return False
        cur2 = conn.cursor()
        cur2.execute("UPDATE verification_codes SET used=1 WHERE id=%s", (row["id"],))
        conn.commit(); cur2.close(); cur.close()
    return True

# ===== Auth =====
def login_required(role=None):
    def deco(fn):
        def wrap(*a, **kw):
            if "user_id" not in session:
                return redirect(url_for("home"))
            if role and session.get("role") != role:
                flash("Vous n’avez pas l’autorisation.", "danger")
                return redirect(url_for("home"))
            return fn(*a, **kw)
        wrap.__name__ = fn.__name__
        return wrap
    return deco

# ===== Routes =====
@app.route("/")
def home():
    if "user_id" in session:
        r = session["role"]
        return redirect(url_for("admin_dashboard" if r=="admin" else
                                "teacher_dashboard" if r=="teacher" else
                                "student_dashboard"))
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username","").strip()
    password = request.form.get("password","")
    with db() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username=%s AND password=SHA2(%s,256)",
                    (username, password))
        u = cur.fetchone(); cur.close()
    if not u:
        flash("Identifiants incorrects.", "danger"); return redirect(url_for("home"))
    if u["phone_verified"] != 1:
        code = create_otp(u["phone"], "register")
        send_sms(u["phone"], f"Votre code de vérification est : {code}")
        session["pending_phone"] = u["phone"]
        flash("Vous devez d’abord valider votre numéro de téléphone.", "warning")
        return redirect(url_for("verify_phone"))
    if u["status"] != "active":
        flash("Compte en attente d’approbation par l’administrateur.", "warning"); return redirect(url_for("home"))
    session.update(user_id=u["id"], role=u["role"], level=u["level"])
    return redirect(url_for("home"))

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("home"))

# --- Inscription étudiant + preuve de paiement + OTP
@app.route("/register", methods=["GET","POST"])
def register():
    levels = ["4as","7D","7O"]
    if request.method == "POST":
        username = request.form.get("username","").strip()
        phone    = request.form.get("phone","").strip()
        password = request.form.get("password","")
        level    = request.form.get("level")
        pfile    = request.files.get("payment_image")

        if not username or not phone or not password or not level:
            flash("Veuillez compléter tous les champs.", "danger"); return redirect(url_for("register"))
        if not pfile or pfile.filename == "":
            flash("Merci de télécharger l’attestation de paiement.", "warning"); return redirect(url_for("register"))
        if not allowed(pfile.filename, IMG_EXT):
            flash("Fichier non autorisé (jpg/png/webp/pdf).", "danger"); return redirect(url_for("register"))

        base = secure_filename(pfile.filename)
        fname = f"{username}_{int(time.time())}_{base}"
        pfile.save(os.path.join(PAY_DIR, fname))

        try:
            with db() as conn:
                cur = conn.cursor()
                cur.execute("""INSERT INTO users (username, phone, password, role, level, status, phone_verified, payment_image)
                               VALUES (%s,%s,SHA2(%s,256),'student',%s,'pending',0,%s)""",
                            (username, phone, password, level, fname))
                conn.commit(); cur.close()
            code = create_otp(phone, "register")
            send_sms(phone, f"Votre code de vérification est : {code}")
            session["pending_phone"] = phone
            flash("Nous avons envoyé un code de vérification par SMS.", "success")
            return redirect(url_for("verify_phone"))
        except IntegrityError as e:
            msg = "Nom d’utilisateur déjà utilisé."
            if "phone" in str(e): msg = "Numéro de téléphone déjà utilisé."
            flash(msg, "danger")
            return redirect(url_for("register"))
    return render_template("register.html", levels=levels)

# --- Saisie du code OTP (vérification du téléphone)
@app.route("/verify", methods=["GET","POST"])
def verify_phone():
    phone = session.get("pending_phone","")
    if request.method == "POST":
        code = request.form.get("otp","").strip()
        phone_form = request.form.get("phone","").strip()
        if phone_form: phone = phone_form
        if not phone or not code:
            flash("Le numéro et le code sont requis.", "danger"); return redirect(url_for("verify_phone"))
        if verify_otp(phone, "register", code):
            with db() as conn:
                cur = conn.cursor()
                cur.execute("UPDATE users SET phone_verified=1 WHERE phone=%s", (phone,))
                conn.commit(); cur.close()
            session.pop("pending_phone", None)
            flash("Numéro vérifié. Votre compte attend l’approbation de l’administrateur.", "success")
            return redirect(url_for("home"))
        else:
            flash("Code invalide ou expiré.", "danger")
    return render_template("verify.html", phone=phone)

# --- Mot de passe oublié
@app.route("/forgot", methods=["GET","POST"])
def forgot():
    if request.method == "POST":
        phone = request.form.get("phone","").strip()
        with db() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT id FROM users WHERE phone=%s", (phone,))
            u = cur.fetchone(); cur.close()
        if not u:
            flash("Aucun compte lié à ce numéro.", "danger"); return redirect(url_for("forgot"))
        code = create_otp(phone, "reset")
        send_sms(phone, f"Code de réinitialisation : {code}")
        session["reset_phone"] = phone
        flash("Un code de réinitialisation a été envoyé par SMS.", "success")
        return redirect(url_for("reset_verify"))
    return render_template("forgot.html")

@app.route("/reset-verify", methods=["GET","POST"])
def reset_verify():
    phone = session.get("reset_phone","")
    if request.method == "POST":
        code = request.form.get("code","").strip()
        newp = request.form.get("new_password","")
        phone_form = request.form.get("phone","").strip()
        if phone_form: phone = phone_form
        if not phone or not code or not newp:
            flash("Tous les champs sont requis.", "danger"); return redirect(url_for("reset_verify"))
        if verify_otp(phone, "reset", code):
            with db() as conn:
                cur = conn.cursor()
                cur.execute("UPDATE users SET password=SHA2(%s,256) WHERE phone=%s", (newp, phone))
                conn.commit(); cur.close()
            session.pop("reset_phone", None)
            flash("Mot de passe réinitialisé. Vous pouvez vous connecter.", "success")
            return redirect(url_for("home"))
        else:
            flash("Code invalide ou expiré.", "danger")
    return render_template("reset_verify.html", phone=phone)

# ===== Tableau de bord Admin =====
@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    with db() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""SELECT id,username,phone,role,level,status,phone_verified,payment_image
                       FROM users ORDER BY id DESC""")
        users = cur.fetchall(); cur.close()
    return render_template("admin.html", users=users)

@app.route("/admin/activate/<int:uid>")
@login_required("admin")
def activate_user(uid):
    with db() as conn:
        cur = conn.cursor(); cur.execute("UPDATE users SET status='active' WHERE id=%s", (uid,))
        conn.commit(); cur.close()
    flash("Compte activé.", "success"); return redirect(url_for("admin_dashboard"))

@app.route("/admin/delete/<int:uid>")
@login_required("admin")
def delete_user(uid):
    with db() as conn:
        cur = conn.cursor(); cur.execute("DELETE FROM users WHERE id=%s", (uid,))
        conn.commit(); cur.close()
    flash("Compte supprimé.", "warning"); return redirect(url_for("admin_dashboard"))

@app.route("/admin/create-teacher", methods=["POST"])
@login_required("admin")
def admin_create_teacher():
    t_user  = request.form.get("t_username","").strip()
    t_phone = request.form.get("t_phone","").strip()
    t_pass  = request.form.get("t_password","")
    t_level = request.form.get("t_level") or None
    if not t_user or not t_phone or not t_pass:
        flash("Nom d’utilisateur, numéro et mot de passe sont requis.", "danger")
        return redirect(url_for("admin_dashboard"))
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute("""INSERT INTO users (username, phone, password, role, level, status, phone_verified)
                           VALUES (%s,%s,SHA2(%s,256),'teacher',%s,'active',1)""",
                        (t_user, t_phone, t_pass, t_level))
            conn.commit(); cur.close()
        flash("Compte enseignant créé.", "success")
    except IntegrityError as e:
        msg = "Nom d’utilisateur déjà utilisé."
        if "phone" in str(e): msg = "Numéro de téléphone déjà utilisé."
        flash(msg, "danger")
    return redirect(url_for("admin_dashboard"))

# ===== Tableau de bord Enseignant =====
@app.route("/teacher", methods=["GET","POST"])
@login_required("teacher")
def teacher_dashboard():
    if request.method == "POST":
        subject = request.form.get("subject")
        chapter = request.form.get("chapter_title","").strip()
        level   = request.form.get("level")
        vfile   = request.files.get("video")
        pfile   = request.files.get("pdf")

        if not subject or not chapter or not level:
            flash("Champs obligatoires manquants.", "danger"); return redirect(url_for("teacher_dashboard"))

        vname = None; pname = None
        if vfile and vfile.filename and allowed(vfile.filename, VIDEO_EXT):
            base = secure_filename(vfile.filename)
            vname = f"{session['user_id']}_{int(time.time())}_{base}"
            vfile.save(os.path.join(VID_DIR, vname))
        if pfile and pfile.filename and allowed(pfile.filename, PDF_EXT):
            base = secure_filename(pfile.filename)
            pname = f"{session['user_id']}_{int(time.time())}_{base}"
            pfile.save(os.path.join(PDF_DIR, pname))

        with db() as conn:
            cur = conn.cursor()
            cur.execute("""INSERT INTO lessons (subject,chapter_title,level,video_file,pdf_file,uploaded_by)
                           VALUES (%s,%s,%s,%s,%s,%s)""",
                        (subject, chapter, level, vname, pname, session["user_id"]))
            conn.commit(); cur.close()
        flash("Leçon ajoutée.", "success")
        return redirect(url_for("teacher_dashboard"))

    with db() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM lessons WHERE uploaded_by=%s ORDER BY uploaded_at DESC",
                    (session["user_id"],))
        my_lessons = cur.fetchall(); cur.close()
    return render_template("teacher.html", lessons=my_lessons)

# ===== Tableau de bord Étudiant =====
@app.route("/student")
@login_required("student")
def student_dashboard():
    level = session.get("level")
    with db() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""SELECT * FROM lessons WHERE level=%s
                       ORDER BY FIELD(subject,'Math','Physique','Chimie','Science naturelle'), uploaded_at DESC""",
                    (level,))
        lessons = cur.fetchall(); cur.close()
    return render_template("student.html", lessons=lessons, level=level)

if __name__ == "__main__":
    print("Uploads:", UP)
app.run(host='0.0.0.0', port=5000, debug=True)

