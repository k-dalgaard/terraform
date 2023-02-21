import base64

user  = base64.b64decode(b'ZW50ZXJfdXNlcg==')
passw  = base64.b64decode(b'cGFzc3dvcmQ=')

username = user.decode('utf-8')
passwd = passw.decode('utf-8')

