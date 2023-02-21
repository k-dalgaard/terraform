import base64

user  = base64.b64decode(<user_base64_token>)
passw  = base64.b64decode(<insert_base64_token>)

username = user.decode('utf-8')
passwd = passw.decode('utf-8')

