import socket, os, time, sys
from Crypto.Cipher import AES

text_to_send = """Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam et feugiat odio. Nullam vitae ante at erat porta rutrum et at mi. Vestibulum nisl orci, lobortis nec arcu quis, pulvinar tristique elit. Praesent facilisis ut nisi quis mattis. Ut quam nibh, lobortis quis ligula vel, rutrum pellentesque risus. In consequat, enim eget laoreet tempor, nibh tellus mollis tortor, nec laoreet ex neque ac mauris. Nullam laoreet at ex eu luctus. Integer tempor euismod ultricies. Vestibulum vitae sagittis massa. Sed ipsum libero, facilisis in mi sit amet, mollis lacinia enim. Aenean et aliquet massa."""

def encrypt_and_return_key(key):
    enc = AES.new(b'sixteen byte key', AES.MODE_ECB, os.urandom(16))
    return enc.encrypt(key)

if len(sys.argv) < 2:
    print('Usage: ./sender.py mode (mode in [\'ecb\', \'cfb\']).')
    exit(0)

if sys.argv[1] not in ['ecb', 'cfb']:
    print('Incorrect encryption standard. Must be either \'ecb\' or \'cfb\'.')
    exit(0)

key = os.urandom(16)
aes = AES.new(key, AES.MODE_ECB, os.urandom(16))

r = socket.socket()
port = 8080
r.connect(('127.0.0.1', port))

# initial handshake
r.send(sys.argv[1].encode())
response = r.recv(2).decode()
if response == 'no':
    print('Negative response received after communicating encryption mode. Exiting...')
    exit(0)
r.send(encrypt_and_return_key(key))

if sys.argv[1] == 'ecb':
    for i in range(0, len(text_to_send), 16):
        plaintext = text_to_send[i:min(len(text_to_send), i + 16)]
        while len(plaintext) < 16: plaintext += " "
        r.send(aes.encrypt(plaintext))
elif sys.argv[1] == 'cfb':
    iv = b'sixteen byte iv '
    for i in range(0, len(text_to_send), 16):
        plaintext = text_to_send[i:min(len(text_to_send), i + 16)]
        while len(plaintext) < 16: plaintext += " "

        # encrypt the iv
        enc_iv = aes.encrypt(iv)

        # xor with the plaintext and send
        cyphertext = bytes([(a ^ b) for a, b in zip(plaintext.encode(), enc_iv)])
        r.send(cyphertext)

        # updating the iv
        iv = cyphertext
else:
    pass

r.close()
