from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)

from datetime import datetime
from database import create_tables, get_connection
from otp_utils import generate_otp, save_otp
from email_utils import send_otp_email

app = Flask(__name__)

app.config["SECRET_KEY"] = "7_seasons-secret-key"

create_tables()

from database import DATABASE
print("Database path:", DATABASE)

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].strip().lower()

        password = request.form["password"]
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
         """
         SELECT * FROM users
         WHERE email = ?
         """,
              (
                   email,
                ),
        )

        user = cursor.fetchone()
        if user is None:

          conn.close()

          flash(
               "Email not found.",
               "error",
            )

          return redirect(url_for("login"))
        print("Stored Hash:", user["password"])
        print("Entered Password:", password)
        if not check_password_hash(
            user["password"],
            password,
       ):
         
         
         print("Password check failed")
         conn.close()


         flash(
              "Incorrect password.",
              "error",
            )

         return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
  
    if request.method == "POST":

        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:

            flash("Passwords do not match.", "error")

            return redirect(url_for("register"))

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        )

        existing_user = cursor.fetchone()

        if existing_user:

            conn.close()

            flash(
                "Email is already registered.",
                "error",
            )

            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO users
            (name,email,password)

            VALUES
            (?,?,?)
            """,
            (
                name,
                email,
                hashed_password,
            ),
        )
        user_id = cursor.lastrowid

        otp = generate_otp()

        save_otp(cursor,user_id, otp)
        send_otp_email(email, otp)
        conn.commit()
        print("User committed successfully")
        conn.close()

        flash(
            "Account created successfully!",
            "success",
        )

        return redirect(url_for("verify_otp"))

    return render_template("register.html")
@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():

    if request.method == "POST":

        otp = request.form["otp"].strip()
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
         """
          SELECT * FROM otp_codes
          WHERE otp = ?
         """,
         (otp,),
       )

        otp_record = cursor.fetchone()
        if otp_record is None:

            flash(
               "Invalid OTP.",
               "error",
            )

            conn.close()

            return redirect(url_for("verify_otp"))
        print("Expires At:", otp_record["expires_at"])
        expires_at = datetime.fromisoformat(
         otp_record["expires_at"]
        )

        current_time = datetime.now()
        if current_time > expires_at:

         conn.close()

         flash(
             "OTP has expired.",
             "error",
            )

         return redirect(url_for("verify_otp"))
        cursor.execute(
            """
            UPDATE users
            SET verified = 1
            WHERE id = ?
          """,
          (
              otp_record["user_id"],
          ),
        ) 
        cursor.execute(
           """
           DELETE FROM otp_codes
           WHERE id = ?
         """,
           (
              otp_record["id"],
            ),
        )
        conn.commit()
        conn.close()
        flash(
          "Email verified successfully!",
          "success",
        )
        return redirect(url_for("login"))
    return render_template("verify_otp.html")
if __name__ == "__main__":
    app.run(debug=True)