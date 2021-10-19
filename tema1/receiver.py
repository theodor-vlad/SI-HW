import socket, os
from Crypto.Cipher import AES

def decrypt_and_return_key(key):
    enc = AES.new(b'sixteen byte key', AES.MODE_ECB, os.urandom(16))
    return enc.decrypt(key)

port = 8080
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', port))
s.listen(5)    
print(f'listening at port {port}...')

c, addr = s.accept()

# primesc cheia criptata, o decriptez si imi fac un block cipher decryptor
mode = c.recv(3).decode()
if mode in ['ecb', 'cfb']:
    c.send(b'ok')
else:
    c.send(b'no')
    exit(0)
encrypted_key = c.recv(16)
key = decrypt_and_return_key(encrypted_key)

block_dec = AES.new(key, AES.MODE_ECB, os.urandom(16))

text_to_print = ""
if mode == 'ecb':
    while True:
        encrypted_block = c.recv(16)
        if len(encrypted_block) == 0:
            break
        text_to_print += block_dec.decrypt(encrypted_block).decode()

    print(text_to_print)
elif mode == 'cfb':
    iv = b'sixteen byte iv '
    while True:
        encrypted_block = c.recv(16)
        if len(encrypted_block) == 0:
            break

        # encrypt the iv
        enc_iv = block_dec.encrypt(iv)

        # xor with the cyphertext
        cyphertext_xor = bytes([(a ^ b) for a, b in zip(encrypted_block, enc_iv)])

        # concatenate the result to the final text
        text_to_print += cyphertext_xor.decode()

        # update the iv
        iv = encrypted_block

    print(text_to_print)
else:
    pass
c.close()