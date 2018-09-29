import hashlib
import binascii

def hash160(secret: bytes):
        secrethash = hashlib.sha256(secret).digest()
        h = hashlib.new('ripemd160')
        h.update(secrethash)
        secret_hash160 = h.digest()
        return secret_hash160

def hash256(bstr: bytes):
    return hashlib.sha256(hashlib.sha256(bstr).digest()).digest()

def sha256(bstr: bytes):
    return hashlib.sha256(bstr).digest()

if __name__ == '__main__':
        h = hash256(binascii.unhexlify('0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000'))
        print('h = %s' % bytes.decode(binascii.hexlify(h)))
        script = '001479091972186c449eb1ded22b78e40d009bdf0089'
        h160 = hash160(binascii.unhexlify(script))
        print('h160 = %s' % bytes.decode(binascii.hexlify(h160)))
        script = '001466d7bffb85fa80f006863750f6565cf481d2b542'
        h160 = hash160(binascii.unhexlify(script))
        print('h160 = %s' % bytes.decode(binascii.hexlify(h160)))
        script = '0014c95fcd5a10525c8c01119cc4e7b894f30361bc4d'
        h160 = hash160(binascii.unhexlify(script))
        print('h160 = %s' % bytes.decode(binascii.hexlify(h160)))
