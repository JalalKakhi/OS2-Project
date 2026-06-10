from flask import Flask, jsonify
import os, socket

app = Flask(__name__)

@app.get("/")
def index():
    return jsonify(app=os.getenv("APP_NAME", "web-app"), host=socket.gethostname())

@app.get("/error")
def error():
    return jsonify(error="simulated operational failure"), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
