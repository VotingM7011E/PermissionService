# PermissionService

## Creating roles dynamically
```
ACCESS_TOKEN=$(curl -s -X POST \                                                                                                       -d "client_id=admin-cli" \
  -d "username=admin" \
  -d "password=XXX" \
  -d "grant_type=password" \
  "https://keycloak-dev.ltu-m7011e-2.se/realms/master/protocol/openid-connect/token" \
  | jq -r .access_token)

curl -X POST   "https://keycloak-dev.ltu-m7011e-2.se/admin/realms/master/roles"   -H "Authorization: Bearer $ACCESS_TOKEN"   -H "Content-Type: application/json"   -d '{
    "name": "my-dynamic-role",
    "description": "Created using API"
}'
```