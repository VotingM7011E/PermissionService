from flask import Flask, request, jsonify
from keycloak_auth import keycloak_protect
from keycloak import KeycloakAdmin
import os
import uuid
import random

keycloak_admin = KeycloakAdmin(
    server_url=os.getenv("KEYCLOAK_URL"),
    username=os.getenv("KEYCLOAK_ADMIN_USERNAME"),
    password=os.getenv("KEYCLOAK_ADMIN_PASSWORD"),
    realm_name=os.getenv("KEYCLOAK_REALM"),
    client_id="admin-cli",
    verify=False  # or False if self-signed certificates
)

app = Flask(__name__)

# Enum for roles
VALID_ROLES = {"view", "vote", "manage"}

# --- Helper validation functions -------------------------------------------

def validate_uuid(id_str):
    try:
        UUID(id_str)
    except Exception:
        abort(400, description=f"Invalid UUID: {id_str}")


def validate_username(username):
    if not isinstance(username, str) or len(username.strip()) == 0:
        abort(400, description="Invalid username")


def validate_role(role):
    if role not in VALID_ROLES:
        abort(400, description=f"Invalid role: {role}. Must be one of {VALID_ROLES}")


# --- Routes -----------------------------------------------------------------

@app.post("/meetings/<meeting_id>/users/<username>/roles/")
def add_role(meeting_id, username):
    # Validate path parameters
    validate_uuid(meeting_id)
    validate_username(username)

    # Validate request body
    data = request.get_json()
    if not data or "role" not in data:
        abort(400, description="Missing 'role' in request body")

    role = data["role"]
    validate_role(role)

    # No actual implementation logic here
    return jsonify({"message": "Role successfully added"}), 200


@app.get("/meetings/<meeting_id>/users/<username>/roles/")
def get_roles(meeting_id, username):
    validate_uuid(meeting_id)
    validate_username(username)

    # No logic, return dummy response structure or empty list
    return jsonify([]), 200


@app.put("/meetings/<meeting_id>/users/<username>/roles/")
def replace_roles(meeting_id, username):
    validate_uuid(meeting_id)
    validate_username(username)

    data = request.get_json()
    if not isinstance(data, list):
        abort(400, description="Body must be an array of roles")

    for role in data:
        validate_role(role)

    # No actual implementation
    return jsonify({"message": "Roles changed"}), 200


@app.delete("/meetings/<meeting_id>/users/<username>/roles/<role>")
def delete_role(meeting_id, username, role):
    validate_uuid(meeting_id)
    validate_username(username)
    validate_role(role)

    # No actual deletion logic
    return jsonify({"message": "Delete successful"}), 200



# Root health check (for Kubernetes)
@app.get("/")
def root():
    return "PermissionService API running"

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
