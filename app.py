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
        uuid.UUID(id_str)
    except Exception:
        abort(400, description=f"Invalid UUID: {id_str}")


def validate_username(username):
    if not isinstance(username, str) or len(username.strip()) == 0:
        abort(400, description="Invalid username")


def validate_role(role):
    if role not in VALID_ROLES:
        abort(400, description=f"Invalid role: {role}. Must be one of {VALID_ROLES}")

# ----------------------------- Keycloak Helpers ------------------------------

def role_name(meeting_id, role):
    """Generate standardized role name."""
    return f"z-{meeting_id}-{role}"

def ensure_role_exists(meeting_id, role):
    """Create Keycloak realm role if it does not exist."""
    rname = role_name(meeting_id, role)

    try:
        keycloak_admin.get_realm_role(rname)
    except:
        # Create the role
        keycloak_admin.create_realm_role({"name": rname})
    
    return keycloak_admin.get_realm_role(rname)

def get_user_id(username):
    users = keycloak_admin.get_users(query={"username": username})
    if not users:
        abort(404, description=f"User '{username}' not found")
    return users[0]["id"]

def get_current_meeting_roles(meeting_id, user_id):
    """Return only roles belonging to this meeting (filter by prefix)."""
    prefix = f"z-{meeting_id}-"
    all_roles = keycloak_admin.get_realm_roles_of_user(user_id=user_id)
    return [r for r in all_roles if r["name"].startswith(prefix)]

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

    user_id = get_user_id(username)

    # Ensure role exists
    role_rep = ensure_role_exists(meeting_id, role)

    # Assign role
    keycloak_admin.assign_realm_roles(user_id=user_id, roles=[role_rep])

    return jsonify({"message": "Role successfully added"}), 200


@app.get("/meetings/<meeting_id>/users/<username>/roles/")
def get_roles(meeting_id, username):
    validate_uuid(meeting_id)
    validate_username(username)

    user_id = get_user_id(username)
    roles = get_current_meeting_roles(meeting_id, user_id)

    # Convert back to logical role names (strip prefix)
    prefix = f"z-{meeting_id}-"
    logical_roles = [r["name"].replace(prefix, "", 1) for r in roles]

    return jsonify(logical_roles), 200


@app.put("/meetings/<meeting_id>/users/<username>/roles/")
def replace_roles(meeting_id, username):
    validate_uuid(meeting_id)
    validate_username(username)

    data = request.get_json()
    if not isinstance(data, list):
        abort(400, description="Body must be an array of roles")

    for role in data:
        validate_role(role)

    user_id = get_user_id(username)

    # Remove old roles for this meeting
    old_roles = get_current_meeting_roles(meeting_id, user_id)
    if old_roles:
        keycloak_admin.delete_realm_roles_of_user(user_id=user_id, roles=old_roles)

    # Assign new roles
    new_role_reps = [ensure_role_exists(meeting_id, r) for r in data]
    if new_role_reps:
        keycloak_admin.assign_realm_roles(user_id=user_id, roles=new_role_reps)

    return jsonify({"message": "Roles changed"}), 200


@app.delete("/meetings/<meeting_id>/users/<username>/roles/<role>")
def delete_role(meeting_id, username, role):
    validate_uuid(meeting_id)
    validate_username(username)
    validate_role(role)

    user_id = get_user_id(username)

    rname = role_name(meeting_id, role)

    try:
        role_rep = keycloak_admin.get_realm_role(rname)
    except:
        abort(404, description=f"Role '{rname}' not found in Keycloak")

    # Remove role from user
    keycloak_admin.delete_realm_roles_of_user(user_id=user_id, roles=[role_rep])

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
