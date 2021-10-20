import socket, os
from Crypto.Cipher import AES

def decrypt_and_return_key(key):
    enc = AES.new(b'sixteen byte key', AES.MODE_ECB, os.urandom(16))
    return enc.decrypt(key)

port = 8080
r = socket.socket()
r.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
r.bind(('', port))
r.listen(5)    
print(f'listening at port {port}...')

s, addr = r.accept()

# primesc cheia criptata, o decriptez si imi fac un block cipher decryptor
mode = s.recv(3).decode()
if mode in ['ecb', 'cfb']:
    s.send(b'ok')
else:
    s.send(b'no')
    exit(0)
encrypted_key = s.recv(16)
key = decrypt_and_return_key(encrypted_key)

aes = AES.new(key, AES.MODE_ECB, os.urandom(16))

text_to_print = ""
if mode == 'ecb':
    while True:
        cyphertext = s.recv(16)
        if len(cyphertext) == 0:
            break
        text_to_print += aes.decrypt(cyphertext).decode()

    print(text_to_print)
elif mode == 'cfb':
    iv = b'sixteen byte iv '
    while True:
        cyphertext = s.recv(16)
        if len(cyphertext) == 0:
            break

        # encrypt the iv
        enc_iv = aes.encrypt(iv)

        # xor with the cyphertext
        plaintext = bytes([(a ^ b) for a, b in zip(cyphertext, enc_iv)]).decode()

        # concatenate the result to the final text
        text_to_print += plaintext

        # update the iv
        iv = cyphertext

    print(text_to_print)
else:
    pass
s.close()