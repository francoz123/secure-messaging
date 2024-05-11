import getpass
import sys

def print_and_exit(msg):
  print(msg)
  sys.exit(1)

def is_ascii(s):
  """ Checks that a string is ASCII only"""
  try:
    s.encode("ascii")
    return True
  except UnicodeEncodeError:
    return False
  

def get_option():
    opt = ''
    err_msg = "Invalid option. Try again"
    user_msg = "Enter option and press enter"
    msg = user_msg

    print(user_msg)
    opt = input("1. Login\n2. Register\n3. Exit\n\nEnter option: ")
    
    while opt != '1' and opt != '2':
        if opt == '3':
           sys.exit(1)
        msg = err_msg
        print(msg)
        opt = input("1. Login\n2. Register\n3. Exit\nEnter option: ")
    
    return opt

def is_strong_password(password):
  upper = lower = digit = special = False

  for c in password:
    if c.isupper():
      upper = True
    elif c.islower():
      lower = True
    elif c.isdigit():
      digit = True
    elif not c.isalnum():
      special = True
  
  return upper and lower and digit and special

def get_username():
  username = input("Enter your username: ")
  while ' ' in username or not is_ascii(username):
    print("Username must not contain spaces and must be ASCII characters only.")
    username = input("Enter your username: ")
  return username

def get_password():
  password = getpass.getpass("Enter your password: ")
  while True:
    if not password:
      print("Passwords is empty.")
      password = getpass.getpass("Enter your password: ")
    else:
      break
  return password

def get_password_with_confirmation():
  password = getpass.getpass("Enter your password: ")
  password_copy = getpass.getpass("confirm your password: ")
  while True:
    if password != password_copy:
      print("Passwords do not match.")
      password = getpass.getpass("Enter your password: ")
      password_copy = getpass.getpass("confirm your password: ")
    elif not is_strong_password(password):
      print("Passwords is not strong. Please chose a strong password.")
      password = getpass.getpass("Enter your password: ")
      password_copy = getpass.getpass("confirm your password: ")
    else:
      break
  return password

def get_user_info():
  username = password = password_copy = auth_type = ''
  opt = get_option()

  if opt == '1':
    username = get_username()
    password = get_password()
    auth_type = 'login'

  if opt == '2':
    username = get_username()
    password = get_password_with_confirmation()
    auth_type = 'register'
  
  return username, password, auth_type  

def ascii_input(prompt):
    """ Gets ASCII input with the given prompt. """
    while True:
        value = input(prompt)
        try:
            value.encode("ascii")
        except UnicodeError:
            print("Please only enter ASCII characters")
        else:
            return value
    

if __name__ == "__main__":
  get_user_info()