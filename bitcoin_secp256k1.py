#from elliptic_curve_math import EllipticCurveMath
import binascii
import random

# Bitcoin Secp256k1 constants [
# generator point
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# field prime
P = 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1

# order
N = (1 << 256) - 0x14551231950B75FC4402DA1732FC9BEBF

a = 0
b = 7

# equation
# y^2 = x^3 + 7
# ]

def point_add(p, q):
    xp, yp = p
    xq, yq = q

    # point doubling 
    if p == q:
        l = pow(2 * yp % P, P - 2, P) * (3 * xp * xp) % P
    # point adding
    else:
        l = pow(xq - xp, P - 2, P) * (yq - yp) % P

    xr = (l ** 2 - xp - xq) % P
    yr = (l * xp - l * xr - yp) % P

    return xr, yr


def point_mul(p, d):
    n = p
    q = None

    for i in range(256):
        if d & (1 << i):
            if q is None:
                q = n
            else:
                q = point_add(q, n)

        n = point_add(n, n)

    return q

# z is message digest
def sign_txn(privkey, z):
    r = 0
    s = 0

    while not r or not s:
        k = random.randrange(1, N)
        x, y = point_mul(G, k)

        r = x % N
        s = ((z + r * privkey) * pow(k, N - 2, N)) % N

    return (r, s)

def verify_signature(pubkey_v, z, sig_v):
    r, s = sig_v

    w = pow(s, N - 2, N)
    u1 = (z * w) % N
    u2 = (r * w) % N

    x, y = point_add(point_mul(G, u1),
                     point_mul(pubkey_v, u2))

    if (r % N) == (x % N):
        return 'signature matches'
    else:
        return 'invalid signature'

class BitcoinSec256k1:
        def privkey2pubkey(self, k: int):
                global G
                K = point_mul(G, k)
                return K

if __name__ == '__main__':

#        bitcoin_sec256k1 = BitcoinSec256k1()
#        while True:
#                privkey_s = input('Enter Private Key: ')
#                privkey_i = int(privkey_s, 16)
#                pubkey = bitcoin_sec256k1.privkey2pubkey(privkey_i)
#                pubkey_c = '04%064x%064x' % (pubkey[0],pubkey[1])
#                print('pubkey = %s' % pubkey_c)
#                pubkey_a = input('verify = ')
#                if pubkey_a == pubkey_c:
#                        print('Right')
#                else:
#                        print('Wrong')

        k = 0x619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9
        Kx, Ky = point_mul(G, k)
        print('(%x, %x)' % (Kx, Ky))
        x = pow(Kx, 1, N)
        print('x = %x' % x)
        sig_v = sign_txn(0x619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9, 0xc37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670)
        print(sig_v)
        
        status = verify_signature((0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00, 
                                        0xe6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f), 
                                0xc37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670, sig_v)
        print(status)
