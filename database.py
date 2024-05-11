import json

def write_credentials(username, password, filename):
    # Create a dictionary with username and password
    credentials = {
        "username": username,
        "password": password
    }
    try:
        # Open the file in write mode
        with open(filename, 'a') as file:
            # Write each credential to the file as a JSON object on a separate line
            json.dump(credentials, file)
            file.write('\n')  # Add a newline character to separate JSON objects
        print("Credentials successfully written to file.")
    except Exception as e:
        print(f"Error writing credentials to file: {e}")
    

def read_credentials(filename):
    # Open the file in read mode
    with open(filename, 'r') as file:
        # Load the JSON data from the file
        credentials = json.load(file)
        return credentials.get("username"), credentials.get("password")
    
def read_all_credentials(filename):
    credentials_list = []

    # Open the file in read mode
    with open(filename, 'r') as file:
        # Read each line (each line contains a JSON object representing a credential)
        for line in file:
            # Load the JSON data from the line
            credentials = json.loads(line)
            credentials_list.append(credentials)
    return credentials_list

if __name__ == '__main__':
    credentials = [
    {"username": "user1", "password": "password1"},
    {"username": "user2", "password": "password2"},
    {"username": "user3", "password": "password3"},
    {"username": "user4", "password": "password4"},
    {"username": "user5", "password": "password5"}
    ]

    for cred in credentials:
        write_credentials(cred['username'], cred['password'], 'data/users.json')

    cred = read_all_credentials('data/users.json')
    print(cred)