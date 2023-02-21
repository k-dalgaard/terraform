import base64
from getpass import getpass

def encode_password(password):
  # Encode the password to base64
  encoded_password = base64.b64encode(password.encode())

  # Return the encoded password
  return encoded_password
# Prompt the user for their password



def update_config_file(hashed_username,hashed_password):
    with open("config_base.py", "r") as f:
        config_file = f.read()
    config_file = config_file.replace("<user_base64_token>", str(hashed_username))
    config_file = config_file.replace("<insert_base64_token>", str(hashed_password))

    f.close()
    
    with open("config.py", "w") as f:
        f.write(config_file)
    f.close()



# Get the password from the user
username = input("enter username to encode: ")
password = getpass("Enter the password to encode: ")

# Encode the password and print the result
encoded_username = encode_password(username)
encoded_password = encode_password(password)
update_config_file(encoded_username,encoded_password)
#update_config_file(encoded_password)
print("Encoded username:", encoded_username)
print("Encoded password:", encoded_password)


