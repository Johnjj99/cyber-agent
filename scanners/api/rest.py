# scanners/api/rest.py
import requests
from typing import List, Dict

GRAPHQL_INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      description
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
"""

def scan(host: str) -> List[Dict]:
    errors = []

    # 1. GraphQL introspection
    try:
        resp = requests.post(f"https://{host}/graphql", json={"query": GRAPHQL_INTROSPECTION_QUERY}, timeout=5)
        if resp.status_code == 200 and "types" in resp.json():
            errors.append({
                "field_path": "graphql_introspection",
                "error_type": "API_MISCONFIG",
                "message": "GraphQL introspection is enabled – exposes schema"
            })
    except:
        pass

    # 2. CORS misconfiguration
    try:
        resp = requests.get(f"https://{host}", headers={"Origin": "https://evil.com"}, timeout=5)
        if resp.headers.get("Access-Control-Allow-Origin") == "*":
            errors.append({
                "field_path": "cors_misconfig",
                "error_type": "API_MISCONFIG",
                "message": "CORS allows any origin (*)"
            })
    except:
        pass

    # 3. Exposed admin endpoints (using a small wordlist)
    admin_paths = ["/admin", "/api/admin", "/panel", "/dashboard", "/manager", "/system"]
    for path in admin_paths:
        try:
            resp = requests.get(f"https://{host}{path}", timeout=3)
            if resp.status_code < 400:
                errors.append({
                    "field_path": f"api_admin_{path.replace('/','')}",
                    "error_type": "API_MISCONFIG",
                    "message": f"Admin endpoint exposed: {path}"
                })
                break
        except:
            pass

    return errors