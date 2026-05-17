from flask import Flask, request, jsonify, render_template
from auth import init_db, register, login, logout, refresh_access_token, verify_access_token
from functools import wraps

app = Flask(__name__)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "message": "Token tidak ditemukan."}), 401
        token = auth_header.split(" ", 1)[1]
        result = verify_access_token(token)
        if not result["ok"]:
            return jsonify({"success": False, "message": result["reason"]}), 401
        request.current_user = result
        return f(*args, **kwargs)
    return decorated

@app.route("/register", methods=["POST"])
def route_register():
    data = request.get_json() or {}
    result = register(data.get("username",""), data.get("email",""), data.get("password",""))
    return jsonify(result), 201 if result["success"] else 400

@app.route("/login", methods=["POST"])
def route_login():
    data = request.get_json() or {}
    result = login(data.get("username",""), data.get("password",""))
    return jsonify(result), 200 if result["success"] else 401

@app.route("/refresh", methods=["POST"])
def route_refresh():
    data = request.get_json() or {}
    result = refresh_access_token(data.get("refresh_token",""))
    return jsonify(result), 200 if result["success"] else 401

@app.route("/logout", methods=["POST"])
def route_logout():
    data = request.get_json() or {}
    result = logout(data.get("refresh_token",""))
    return jsonify(result), 200 if result["success"] else 400

@app.route("/me", methods=["GET"])
@require_auth
def route_me():
    return jsonify({"success": True, "user": request.current_user}), 200

@app.route("/", methods=["GET"])
def route_index():
    return render_template("index.html")

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
