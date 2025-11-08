# app.py
"""
Full Flask app for Phishing Detection site with:
 - site-wide login (session)
 - MongoDB integration for dataset and logs
 - Train model from MongoDB
 - Analyze URL and Analyze Email endpoints
 - Dashboard and utility routes
 - Confidence override: classify as phishing when confidence <= CONFIDENCE_THRESHOLD

Requirements:
  pip install flask pymongo python-dotenv pandas scikit-learn requests beautifulsoup4
Make sure feature.py exists and exports FeatureExtraction and FEATURE_COLS
"""

import os
import pickle
import numpy as np
import pandas as pd
from functools import wraps
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    jsonify, session, send_from_directory
)
from pymongo import MongoClient
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from werkzeug.security import generate_password_hash, check_password_hash


# load environment variables
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "super_secret_key")

# --------------------------
# MongoDB Connection
# --------------------------
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB", "phishing_detection")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION", "training_data")
USERS_COLLECTION = os.getenv("USERS_COLLECTION", "users")

if not MONGO_URI:
    raise RuntimeError("MONGO_URI missing! Add it in .env")

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]

collection = db[MONGO_COLLECTION]
users_col = db[USERS_COLLECTION]

# -------------------------
# Config
# -------------------------
MONGO_URI = os.getenv("MONGO_URI", None)
MONGO_DB = os.getenv("MONGO_DB", "phishing_detection")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION", "training_data")
MODEL_FILE = os.getenv("MODEL_FILE", "model.pkl")

# Confidence threshold default (60.39% => 0.6039)
CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", 0.6039))

# Admin credentials for simple session login (put secure values in .env)
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# -------------------------
# App init
# -------------------------
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = os.getenv("FLASK_SECRET", "change_this_secret_for_prod")
@app.route('/')
def index():
    return render_template('index.html')

# -------------------------
# Authentication (Sign up + Login + Logout)
# -------------------------
from werkzeug.security import generate_password_hash, check_password_hash

USERS_COLLECTION = os.getenv("USERS_COLLECTION", "users")
users_col = db[USERS_COLLECTION]

# ----------------------------------------------------
# 4️⃣  LOGOUT
# ----------------------------------------------------
@app.route("/logout")
def logout():
    session.clear()
    flash("👋 Logged out successfully!", "info")
    return redirect(url_for("login"))


# -------------------------
# Mongo client
# -------------------------
if not MONGO_URI:
    raise RuntimeError("MONGO_URI not set in environment. Add it to .env or environment variables.")
client = MongoClient(MONGO_URI)
db = client[MONGO_DB]
collection = db[MONGO_COLLECTION]
users_col = db[os.getenv("USERS_COLLECTION", "users")]


# -------------------------
# Feature extractor import
# -------------------------
# feature.py must be present and export FeatureExtraction + FEATURE_COLS
try:
    from feature import FeatureExtraction, FEATURE_COLS
except Exception as e:
    # allow import error to surface later, but keep app importable for edits
    FeatureExtraction = None
    FEATURE_COLS = []
    app.logger.warning(f"Could not import feature.py: {e}")

# ----------------------------------------------------
# 🧩 SIGN-UP PAGE (first page)
# ----------------------------------------------------
@app.route('/')
def home():
    """Show signup page first if not logged in"""
    if session.get("logged_in"):
        return redirect(url_for("index"))
    return redirect(url_for("signup"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Sign up: create user and go to login"""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()
        confirm = (request.form.get("confirm_password") or "").strip()

        if not email or not password or not confirm:
            flash("⚠️ All fields are required.", "error")
            return redirect(url_for("signup"))

        if password != confirm:
            flash("❌ Passwords do not match.", "error")
            return redirect(url_for("signup"))

        existing_user = users_col.find_one({"email": email})
        if existing_user:
            flash("ℹ️ Account already exists. Please log in.", "info")
            return redirect(url_for("login"))

        hashed_pw = generate_password_hash(password)
        users_col.insert_one({"email": email, "password": hashed_pw})
        flash("✅ Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


# ----------------------------------------------------
# 🧩 LOGIN PAGE
# ----------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    """Login: authenticate user and go to index"""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()

        user = users_col.find_one({"email": email})
        if not user:
            flash("⚠️ Account not found. Please sign up first.", "error")
            return redirect(url_for("signup"))

        if not check_password_hash(user["password"], password):
            flash("❌ Incorrect password. Try again.", "error")
            return redirect(url_for("login"))

        session["logged_in"] = True
        session["email"] = email
        flash("✅ Logged in successfully!", "success")
        return redirect(url_for("index"))

    return render_template("login.html")


# -------------------------
# Authentication: site-wide
# -------------------------
@app.before_request
def require_login():
    """
    Enforce login for all routes except 'login', 'static', and 'favicon'.
    If you have other public endpoints, add their endpoint names to allowed_endpoints.
    """
    allowed_endpoints = {"login", "signup", "static", "favicon"}  # add other public endpoint names here
    # request.endpoint may be None in some calls — guard it
    endpoint = request.endpoint
    if endpoint and endpoint not in allowed_endpoints and not session.get("logged_in"):
        return redirect(url_for("login"))

# -------------------------
# Helper functions
# -------------------------
def load_from_mongo():
    """Load all documents from training collection into a pandas DataFrame."""
    docs = list(collection.find())
    if not docs:
        return pd.DataFrame()
    df = pd.DataFrame(docs)
    if "_id" in df.columns:
        df = df.drop(columns=["_id"])
    return df


def detect_label_mapping(df):
    """
    Detect typical label mapping in the 'Result' column.
    Common cases:
      -1 => phishing, 1 => legitimate
       1 => phishing, 0 => legitimate
    Returns a mapper function v -> 1 (phish) or 0 (legit)
    """
    vals = sorted(df["Result"].dropna().unique().tolist())
    if -1 in vals:
        return lambda v: 1 if int(v) == -1 else 0
    if 1 in vals and 0 in vals:
        return lambda v: 1 if int(v) == 1 else 0
    # fallback: treat 1 as phishing
    return lambda v: 1 if int(v) == 1 else 0


def train_and_save_model(df):
    """Train RandomForest on data frame and save model + feature_cols as a dict."""
    if "Result" not in df.columns:
        raise ValueError("No 'Result' column found in DB data.")

    df_clean = df.drop(columns=["Id"], errors="ignore").copy()

    mapper = detect_label_mapping(df_clean)
    y = df_clean["Result"].map(mapper)

    # pick features: prefer FEATURE_COLS intersection
    available_features = [c for c in FEATURE_COLS if c in df_clean.columns]
    if not available_features:
        available_features = df_clean.select_dtypes(include=[np.number]).columns.tolist()
        available_features = [c for c in available_features if c != "Result"]

    if not available_features:
        raise ValueError("No numeric feature columns available for training.")

    X = df_clean[available_features].fillna(0)

    model = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1)

    strat = y if len(y.unique()) > 1 else None
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=strat)

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, zero_division=0)

    # Save a dict to avoid earlier pickle format bug
    with open(MODEL_FILE, "wb") as f:
        pickle.dump({"model": model, "feature_cols": available_features}, f)

    return {"accuracy": acc, "report": report, "feature_cols": available_features}


def load_saved_model():
    """Load saved model dict from MODEL_FILE and validate format."""
    if not os.path.exists(MODEL_FILE):
        return None
    with open(MODEL_FILE, "rb") as f:
        saved = pickle.load(f)
    if not isinstance(saved, dict) or "model" not in saved or "feature_cols" not in saved:
        raise ValueError("Saved model file has unexpected format. Retrain to create proper file.")
    return saved

# -------------------------
@app.route("/train_from_mongo", methods=["GET"])
def train_from_mongo():
    """Train model from MongoDB collection and save to disk."""
    df = load_from_mongo()
    if df.empty:
        flash("No data found in MongoDB collection.", "error")
        return redirect(url_for("index"))
    try:
        res = train_and_save_model(df)
        flash(f"Model trained. Test accuracy: {res['accuracy']*100:.2f}%", "success")
        return render_template("result.html", accuracy=res["accuracy"], report=res["report"])
    except Exception as e:
        flash(f"Training failed: {e}", "error")
        return redirect(url_for("index"))


@app.route("/analyze_url", methods=["POST"])
def analyze_url():
    """Extract features from the posted URL, predict, and log the result, then show result page."""
    if FeatureExtraction is None:
        flash("feature.py not available. Cannot extract URL features.", "error")
        return render_template("url_check.html", error="FeatureExtraction not found")

    url = (request.form.get("url") or "").strip()
    if not url:
        flash("Please enter a URL.", "error")
        return render_template("url_check.html", error="No URL provided")

    try:
        saved = load_saved_model()
    except Exception as e:
        flash(f"Failed to load model: {e}", "error")
        return render_template("url_check.html", error=str(e))

    if not saved:
        flash("No trained model found. Please train first.", "error")
        return render_template("url_check.html", error="Model not found")

    model = saved["model"]
    feature_cols = saved["feature_cols"]

    try:
        fe = FeatureExtraction(url=url)
        numeric_dict, _ = fe.extract_all()
    except Exception as e:
        flash(f"Feature extraction failed: {e}", "error")
        return render_template("url_check.html", error=f"Feature extraction failed: {e}")

    row = [numeric_dict.get(col, 0) for col in feature_cols]
    X = np.array(row).reshape(1, -1)

    try:
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X)[0]
            confidence = float(probs.max())
        else:
            confidence = None
        pred = int(model.predict(X)[0])
    except Exception as e:
        flash(f"Prediction error: {e}", "error")
        return render_template("url_check.html", error=f"Prediction error: {e}")

    # Apply confidence threshold rule
    if confidence is not None and confidence <= CONFIDENCE_THRESHOLD:
        label = f"Phishing (confidence ≤ {CONFIDENCE_THRESHOLD * 100:.2f}%)"
        numeric_pred = 1
    else:
        label = "Phishing" if pred == 1 else "Legitimate"
        numeric_pred = pred

    # Log in MongoDB
    try:
        log_doc = {**numeric_dict}
        log_doc.update({
            "Result": -1 if numeric_pred == 1 else 1,
            "analyzed_url": url,
            "source": "analyze_url",
            "confidence": confidence
        })
        collection.insert_one(log_doc)
    except Exception:
        app.logger.exception("Failed to log analyzed URL")

    # Show result on the same page instead of redirect
    conf_display = f"{confidence * 100:.2f}%" if confidence is not None else "N/A"

    return render_template(
        "url_check.html",
        url=url,
        label=label,
        confidence=conf_display,
        result_numeric=numeric_pred
    )


@app.route("/analyze_email", methods=["POST"])
def analyze_email():
    """Analyze the pasted raw email, extract features, predict phishing/legit, and show result."""
    if FeatureExtraction is None:
        flash("⚠️ feature.py not available. Cannot extract email features.", "error")
        return render_template("email_check.html", error="FeatureExtraction not found")

    raw_email = (request.form.get("raw_email") or "").strip()
    if not raw_email:
        flash("Please paste an email (headers + body).", "error")
        return render_template("email_check.html", error="No email provided")

    try:
        saved = load_saved_model()
    except Exception as e:
        flash(f"Failed to load model: {e}", "error")
        return render_template("email_check.html", error=f"Failed to load model: {e}")

    if not saved:
        flash("No trained model found. Please train first.", "error")
        return render_template("email_check.html", error="Model not found")

    model = saved["model"]
    feature_cols = saved["feature_cols"]

    try:
        fe = FeatureExtraction(raw_email=raw_email)
        numeric_dict, _ = fe.extract_all()
    except Exception as e:
        flash(f"Feature extraction failed: {e}", "error")
        return render_template("email_check.html", error=f"Feature extraction failed: {e}")

    row = [numeric_dict.get(col, 0) for col in feature_cols]
    X = np.array(row).reshape(1, -1)

    try:
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X)[0]
            confidence = float(probs.max())
        else:
            confidence = None
        pred = int(model.predict(X)[0])
    except Exception as e:
        flash(f"Prediction error: {e}", "error")
        return render_template("email_check.html", error=f"Prediction error: {e}")

    # Confidence threshold rule
    if confidence is not None and confidence <= CONFIDENCE_THRESHOLD:
        label = "Phishing"
        numeric_pred = 1
    else:
        label = "Phishing" if pred == 1 else "Legitimate"
        numeric_pred = pred

    # Log result
    try:
        doc = {
            "RawEmail": raw_email,
            **numeric_dict,
            "Result": -1 if numeric_pred == 1 else 1,
            "source": "analyze_email",
            "confidence": confidence,
        }
        collection.insert_one(doc)
    except Exception:
        app.logger.exception("Failed to log analyzed email")

    # Show the result directly in the same page
    return render_template(
        "email_check.html",
        email_text=raw_email,
        label=label,
        result_numeric=numeric_pred,
    )



@app.route("/dashboard")
def dashboard():
    """
    Basic dashboard: uses logged analyze records (source analyze_url/analyze_email)
    to compute counts and percentages.
    """
    try:
        data = list(collection.find({"source": {"$in": ["analyze_url", "analyze_email"]}}))
        total = len(data)
        if total == 0:
            flash("No analyzed data available for dashboard yet.", "info")
            return redirect(url_for("index"))

        df = pd.DataFrame(data)
        phishing_count = int((df["Result"] == -1).sum()) if "Result" in df.columns else 0
        legit_count = total - phishing_count
        phishing_percent = round((phishing_count / total) * 100, 2) if total else 0.0
        legit_percent = round((legit_count / total) * 100, 2) if total else 0.0

        # average confidence if available
        confs = [float(d.get("confidence")) for d in data if d.get("confidence") is not None]
        avg_conf = round(np.mean(confs) * 100, 2) if confs else None

        model_acc = None
        if os.path.exists(MODEL_FILE):
            try:
                saved = load_saved_model()
                # we don't have stored test accuracy in the model file; user sees accuracy after training page
            except Exception:
                model_acc = None

        return render_template(
            "dashboard.html",
            total=total,
            phishing_count=phishing_count,
            legit_count=legit_count,
            phishing_percent=phishing_percent,
            legit_percent=legit_percent,
            avg_conf=avg_conf,
            model_acc=model_acc
        )
    except Exception as e:
        flash(f"Error loading dashboard: {e}", "error")
        return redirect(url_for("index"))


# -------------------------
# API helpers
# -------------------------
@app.route("/predict_features", methods=["POST"])
def predict_features():
    """POST JSON with {features: {col:val,...}} or {features_list: [...]}. Returns JSON result."""
    saved = load_saved_model()
    if not saved:
        return jsonify({"error": "No trained model found. Train first."}), 400
    model = saved["model"]
    feature_cols = saved["feature_cols"]

    payload = request.get_json(silent=True) or request.form.to_dict()
    # prefer dict form
    features_dict = payload.get("features") if isinstance(payload, dict) else None
    features_list = payload.get("features_list") if isinstance(payload, dict) else None

    if features_dict:
        try:
            row = [float(features_dict[col]) for col in feature_cols]
        except Exception as e:
            return jsonify({"error": f"Invalid features dict: {e}"}), 400
    elif features_list:
        try:
            row = [float(x) for x in features_list]
            if len(row) != len(feature_cols):
                return jsonify({"error": "features_list length mismatch"}), 400
        except Exception as e:
            return jsonify({"error": f"Invalid features_list: {e}"}), 400
    else:
        return jsonify({"error": "Provide 'features' or 'features_list' in JSON body."}), 400

    X = np.array(row).reshape(1, -1)
    confidence = None
    try:
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X)[0]
            confidence = float(probs.max())
        pred = int(model.predict(X)[0])
    except Exception as e:
        return jsonify({"error": f"Prediction failed: {e}"}), 500

    if confidence is not None and confidence <= CONFIDENCE_THRESHOLD:
        label = f"Phishing (confidence ≤ {CONFIDENCE_THRESHOLD*100:.2f}%)"
    else:
        label = "Phishing" if pred == 1 else "Legitimate"

    return jsonify({"label": label, "prediction": int(pred), "confidence": confidence, "feature_cols": feature_cols})


@app.route("/add_sample", methods=["POST"])
def add_sample():
    """Insert a JSON document into MongoDB training collection (must include Result)."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    if "Result" not in data:
        return jsonify({"error": "Field 'Result' required (use -1 for phishing, 1 for legit)"}), 400
    try:
        collection.insert_one(data)
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/clear_model", methods=["POST"])
def clear_model():
    """Delete saved model file."""
    if os.path.exists(MODEL_FILE):
        try:
            os.remove(MODEL_FILE)
            return jsonify({"status": "deleted"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"status": "no_model"})
# --- Page Routes --- #

@app.route("/url_check")
def url_check():
    return render_template("url_check.html")

@app.route("/email_check")
def email_check():
    return render_template("email_check.html")

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    # debug mode suitable for development only
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
