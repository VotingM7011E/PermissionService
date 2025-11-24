from flask import Flask, request, jsonify
from keycloak_auth import keycloak_protect
import os
import uuid
import random

app = Flask(__name__)

# Root health check (for Kubernetes)
@app.get("/")
def root():
    return "MeetingService API running"

@app.route("/private")
@keycloak_protect
def private():
    return jsonify({
        "message": "Protected route",
        "user": request.user
    })

@app.route("/public")
def public():
    return {"message": "Public route"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
