import base64

def decode_base64(token):
    # decode the token
    decoded_token = base64.b64decode(token).decode('utf-8')
    return decoded_token

# test the function
token = input("enter base64 token to decode: ")
print(decode_base64(token))
