from flask import Flask, request, jsonify
from keycloak_auth import keycloak_protect, check_role
from keycloak import KeycloakAdmin
from mq import start_consumer
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
        raise ValueError(f"Invalid UUID: {id_str}")


def validate_username(username):
    if not isinstance(username, str) or len(username.strip()) == 0:
        raise ValueError(f"Invalid username: {username}")


def validate_role(role):
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}. Must be one of {VALID_ROLES}")

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
        raise RuntimeError(f"User '{username}' not found")
    return users[0]["id"]

def get_current_meeting_roles(meeting_id, user_id):
    """Return only roles belonging to this meeting (filter by prefix)."""
    prefix = f"z-{meeting_id}-"
    all_roles = keycloak_admin.get_realm_roles_of_user(user_id=user_id)
    return [r for r in all_roles if r["name"].startswith(prefix)]

# --- Internal logic -----------------------------------------------------------------

def add_role_to_user(meeting_id, username, role):
    validate_uuid(meeting_id)
    validate_username(username)
    validate_role(role)

    user_id = get_user_id(username)
    
    role_rep = ensure_role_exists(meeting_id, role)

    # Assign role
    keycloak_admin.assign_realm_roles(user_id=user_id, roles=[role_rep])

# --- Routes -----------------------------------------------------------------

@app.post("/meetings/<meeting_id>/users/<username>/roles/")
@keycloak_protect
def add_role(meeting_id, username):
    # Validate path parameters
    validate_uuid(meeting_id)
    user_id = request.user["preferred_username"]
    if not user_id: 
        return jsonify({"error": "Unauthorized'"}), 401

    if not check_role(request.user, meeting_id, "manage"):
        return jsonify({"error": "Forbidden"}), 403

    validate_username(username)

    # Validate request body
    data = request.get_json()
    if not data or "role" not in data:
        abort(400, description="Missing 'role' in request body")

    add_role_to_user(meeting_id, username, role)

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
@keycloak_protect
def replace_roles(meeting_id, username):
    validate_uuid(meeting_id)
    user_id = request.user["preferred_username"]
    if not user_id: 
        return jsonify({"error": "Unauthorized'"}), 401

    if not check_role(request.user, meeting_id, "manage"):
        return jsonify({"error": "Forbidden"}), 403

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
@keycloak_protect
def delete_role(meeting_id, username, role):
    validate_uuid(meeting_id)
    user_id = request.user["preferred_username"]
    if not user_id: 
        return jsonify({"error": "Unauthorized'"}), 401

    if not check_role(request.user, meeting_id, "manage"):
        return jsonify({"error": "Forbidden"}), 403

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

@app.get("/meetings/<meeting_id>/roles/<role>/users")
def get_users_with_role(meeting_id, role):
    """
    GET /meetings/{meeting_id}/roles/{role}/users
    Get all users with a specific role in a meeting. 
    """
    validate_uuid(meeting_id)
    validate_role(role)
    rname = role_name(meeting_id, role)

    try:
        # Get all users assigned to this role
        role_users = keycloak_admin.get_realm_role_members(rname)
    except Exception: 
        # Role doesn't exist, return empty list
        return jsonify([]), 200

    # Extract usernames from the user representations
    usernames = [user.get("username") for user in role_users if user.get("username")]

    return jsonify(usernames), 200

# --- Inter-service -----------------

def on_event(event: dict):
    # event envelope: {event_type, data, ...}
    et = event.get("event_type")
    data = event.get("data", {})

    if et == "permission.create_meeting":
        # {
        #    meeting_id: uuid
        #    creator_username: username
        # }
        if not data:
            raise Exception("Missing data")
        if "meeting_id" not in data:
            raise Exception("Missing meeting_id in data")
        if "creator_username" not in data:
            raise Exception("Missing creator_username in data")
        
        add_role_to_user(data["meeting_id"], data["creator_username"], "view")
        add_role_to_user(data["meeting_id"], data["creator_username"], "manage")

# Start consumer thread (after app exists)
start_consumer(
    queue=os.getenv("MQ_QUEUE", "permission-service"),
    bindings=os.getenv("MQ_BINDINGS", "permission.create_meeting").split(","),
    on_event=on_event,
)

# Root health check (for Kubernetes)
@app.get("/")
def root():
    return "PermissionService API running"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
