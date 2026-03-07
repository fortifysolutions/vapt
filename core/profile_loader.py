# core/profile_loader.py
import json

def load_profile(profile_name):
    path = f"profiles/{profile_name}.json"
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return data["modules"]
    except FileNotFoundError:
        print(f"[!] Profile '{profile_name}' not found at {path}.")
        return []
    except json.JSONDecodeError:
        print(f"[!] Profile '{profile_name}' contains invalid JSON formatting.")
        return []