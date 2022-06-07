from hashlib import sha256


def cryptage(var, shared_secret):
    PATH_crypte_recu = 'C:\\Users\\User\\PycharmProjects\Yessodot_Rechatot\\testcrypterecu1.txt'
    PATH_DECRYPT = 'C:\\Users\\User\\PycharmProjects\Yessodot_Rechatot\\testdecrypterecu1.txt'

    keys = sha256(str(shared_secret).encode()).digest()
    # strip down the packet to the payload itself
    if type(var) == bytes:
        with open(PATH_crypte_recu, 'wb') as f_entree:
            f_entree.write(var)
    else:
        with open(PATH_crypte_recu, 'wb') as f_entree:
            f_entree.write(var.encode('ansi'))

    with open(PATH_crypte_recu, 'rb') as f_entree2:
        with open(PATH_DECRYPT, 'wb') as f_sortie:
            i = 0
            while f_entree2.peek():
                c = ord(f_entree2.read(1))
                j = i % len(keys)
                b = bytes([c ^ keys[j]])
                f_sortie.write(b)
                i = i + 1
    text = open(PATH_DECRYPT, 'rb').read()
    return text
