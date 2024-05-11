import hashlib
import json

def hash_password(password):
    # Hash the password using SHA-256
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return password_hash

def save_to_json(filename, hashed_password):
    data = {"hashed_password": hashed_password}
    with open(filename, 'w') as json_file:
        json.dump(data, json_file, indent=4)

if __name__ == "__main__":
    user_password = input("Enter your password: ")
    hashed_result = hash_password(user_password)
    save_to_json("hashed_password.json", hashed_result)
    print("Password hash saved to 'hashed_password.json'", hashed_result)