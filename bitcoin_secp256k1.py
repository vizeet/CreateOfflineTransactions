from elliptic_curve_math import EllipticCurveMath
import binascii

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

class BitcoinSec256k1:
        def privkey2pubkey(self, k: int):
                global G
                K = point_mul(G, k)
                return K

if __name__ == '__main__':

        bitcoin_sec256k1 = BitcoinSec256k1()
        while True:
                privkey_s = input('Enter Private Key: ')
                privkey_i = int(privkey_s, 16)
#               pubkey = bitcoin_sec256k1.privkey2pubkey(0x18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725)
                pubkey = bitcoin_sec256k1.privkey2pubkey(privkey_i)
                pubkey_c = '04%064x%064x' % (pubkey[0],pubkey[1])
                print('pubkey = %s' % pubkey_c)
                pubkey_a = input('verify = ')
                if pubkey_a == pubkey_c:
                        print('Right')
                else:
                        print('Wrong')
