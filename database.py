import json

def write_credentials(username, password, filename):
    """
        Writes user credentials to file

        Args:
            username (str)
            password (str)
            filename (str)
        Return:
            None
    """
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
    
def save_public_key(username, public_key, filename):
    """
        Writes user public key to file

        Args:
            public_key (str)
            filename (str)
        Return:
            None
    """
    # Create a dictionary with username and password
    key = {
        'username': username, 'key': public_key,
    }
    try:
        # Open the file in write mode
        with open(filename, 'a') as file:
            # Write public key to the file as a JSON object on a separate line
            json.dump(key, file)
            file.write('\n')  # Add a newline character to separate JSON objects
    except Exception as e:
        print(f"Error writing credentials to file: {e}")

def load_public_keys(filename):
    """
        Loades user public keys from file into a dictionary

        Args:
            filename (str): file name
        Return:
            dict
    """
    keys = {}

    # Open the file in read mode
    with open(filename, 'r') as file:
        # Read each line (each line contains a JSON object representing a credential)
        for line in file:
            # Load the JSON data from the line
            key_dict = json.loads(line)
            keys[key_dict['username']] = key_dict['key']
    print(keys)
    return keys

def read_credentials(filename):
    # Open the file in read mode
    with open(filename, 'r') as file:
        # Load the JSON data from the file
        credentials = json.load(file)
        return credentials.get("username"), credentials.get("password")
    
def read_all_credentials(filename):
    """
        Loades user credentials from file into a list

        Args:
            filename (str): file name
        Return:
            list: list of user credentials
    """
    credentials_list = []

    # Open the file in read mode
    with open(filename, 'r') as file:
        # Read each line (each line contains a JSON object representing a credential)
        for line in file:
            # Load the JSON data from the line
            credentials = json.loads(line)
            credentials_list.append(credentials)
    return credentials_list

def load_users(filename):
    """
        Loades user credentials from file into a dictionary

        Args:
            filename (str): file name
        Return:
            dict:
    """
    users = {}

    # Open the file in read mode
    with open(filename, 'r') as file:
        # Read each line (each line contains a JSON object representing a credential)
        for line in file:
            # Load the JSON data from the line
            credentials = json.loads(line)
            users[credentials['username']] = credentials
    return users

if __name__ == '__main__':
    username = 'hello'
    key = {
        username: 'public_key',
    }
    print (key)