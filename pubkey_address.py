from utility_adapters import bitcoin_secp256k1
from utility_adapters.bitcoin_secp256k1 import P
import binascii
from utility_adapters import bitcoin_base58
from utils import base58
from utility_adapters import hash_utils
from utils import bech32
import hashlib

network_type = ['mainnet', 'testnet', 'regtest']
segwit_address_prefix = {'mainnet': 'bc', 'testnet': 'tb', 'regtest': 'bcrt'}
address_prefix = {'mainnet': ['1'], 'testnet': []}

# uncompressed public key has b'\x04' prefix
def compressPubkey(pubkey: bytes):
        x_b = pubkey[1:33]
        y_b = pubkey[33:65]
        if (y_b[31] & 0x01) == 0: # even
                compressed_pubkey = b'\x02' + x_b
        else:
                compressed_pubkey = b'\x03' + x_b
        return compressed_pubkey

def privkey2pubkey(privkey: int, compress: bool):
        bitcoin_sec256k1 = bitcoin_secp256k1.BitcoinSec256k1()
        pubkey = bitcoin_sec256k1.privkey2pubkey(privkey)
        full_pubkey = b'\x04' + binascii.unhexlify(str('%064x' % pubkey[0])) + binascii.unhexlify(str('%064x' % pubkey[1]))
        if compress == True:
                compressed_pubkey = compressPubkey(full_pubkey)
                return compressed_pubkey
        return full_pubkey

def uncompressPubkey(x_b: bytes):
        prefix = x_b[0:1]
        print('prefix = %s' % prefix)
        print('(p+1)/4 = %d' % ((P + 1) >> 2))
        x_b = x_b[1:33]
        x = int.from_bytes(x_b, byteorder='big')

        y_square = (pow(x, 3, P)  + 7) % P
        y_square_square_root = pow(y_square, ((P+1) >> 2), P)
        if (prefix == b"\x02" and y_square_square_root & 1) or (prefix == b"\x03" and not y_square_square_root & 1):
            y = (-y_square_square_root) % P
        else:
            y = y_square_square_root

        y_b = y.to_bytes(32, 'big')
        full_pubkey_b = b''.join([b'\x04', x_b, y_b])
        return full_pubkey_b

### pre-segwit [
def pkh2address(pkh: bytes, nettype: str):
        address = bitcoin_base58.forAddress(pkh, nettype, False)
        return address

def sh2address(sh: bytes, nettype: str):
        address = bitcoin_base58.forAddress(sh, nettype, True)
        return address

def redeemScript2address(script: bytes, nettype: str):
        sh = hash_utils.hash160(script)
        address = sh2address(sh, nettype)
        return address

### ] segwit [
def hash2segwitaddr(witprog: bytes, nettype: str):
        witver = 0x00
        hrp = segwit_address_prefix[nettype]
        print('hrp = %s' % hrp)
        address = witnessProgram2address(hrp, witver, witprog)
        return address

def pubkey2segwitaddr(pubkey: bytes, nettype: str):
        pkh = hash_utils.hash160(pubkey)
        print('pkh = %s' % bytes.decode(binascii.hexlify(pkh)))
        address = hash2segwitaddr(pkh, nettype)
        return address
### ]

def pubkey2address(pubkey: bytes, nettype: str, is_segwit: bool):
        pkh = hash_utils.hash160(pubkey)
        print('pkh = %s' % bytes.decode(binascii.hexlify(pkh)))
        address = hash2address(pkh, nettype, is_segwit, is_script=False)
        return address

def hash2address(h: bytes, nettype: str, is_segwit: bool, is_script: bool):
        if is_script:
                if is_segwit:
                        address = hash2segwitaddr(h, nettype)
                else:
                        address = sh2address(h, nettype == 'testnet')
        else:
                if is_segwit:
                        address = hash2segwitaddr(h, nettype)
                else:
                        address = pkh2address(h, nettype == 'testnet')
        return address

def address2hash(address: str):
        is_segwit = (address[0:3] == 'bc1' or address[0:3] == 'tb1' or address[0:5] == 'bcrt1')
        if is_segwit:
                hrp, h_list = bech32.bech32_decode(address)
                witver, h_list = bech32.decode(hrp, address)
                print('h_list = %s' % h_list)
                h_b = bytes(h_list)
        else:
                #h_b = base58.base58checkDecode(privkey_wif)
                print('IIIIII address = %s' % address)
                h_b = base58.base58checkDecode(address)
        return h_b

def addressCheckVerify(address: str):
        is_valid = False
        if address[0] in ['1', '3', 'm', 'n', '2']:
                is_valid = bitcoin_base58.addressVerify(address)
        elif address[0:3] in [
                                'bc1', # mainnet
                                'tb1', # testnet
                                'bcrt1' # regtest
                             ]:
                is_valid = bech32.addressVerify(address)
        return is_valid

def witnessProgram2address(hrp: str, witver: int, witprog: bytes):
        return bech32.encode(hrp, witver, witprog)

def privkeyHex2Wif(privkey: int, nettype: str, for_compressed_pubkey: bool):
        wif = bitcoin_base58.encodeWifPrivkey(privkey, nettype, for_compressed_pubkey)
        return wif

def privkeyWif2Hex(privkey: str):
        nettype, prefix, privkey, for_compressed_pubkey = bitcoin_base58.decodeWifPrivkey(privkey)
        return privkey

if __name__ == '__main__':
        pubkey = privkey2pubkey(0x18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725, False)
        print ('Full pubkey = %s' % bytes.decode(binascii.hexlify(pubkey)))
        pubkey = privkey2pubkey(0x18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725, True)
        print ('compressed pubkey = %s' % bytes.decode(binascii.hexlify(pubkey)))
        privkey_i = 0xe01995f9fa6be4f08511cbebc0a26741c38192026acab874c8c640331cdb98a8
        pubkey = privkey2pubkey(privkey_i, True)
        print ('compressed pubkey = %s for privkey = %x' % (bytes.decode(binascii.hexlify(pubkey)), privkey_i))
        address = pubkey2address(pubkey, "mainnet", False)
        print('address = %s' % address)
        pubkey = uncompressPubkey(pubkey)
        print ('uncompressed pubkey = %s' % bytes.decode(binascii.hexlify(pubkey)))
        is_valid = addressCheckVerify(address)
        print('Is Address valid: %r' % is_valid)
        h160 = 'e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a'
        address = sh2address(binascii.unhexlify(h160), False)
        print ('P2SH address = %s' % address)
        is_valid = addressCheckVerify(address)
        print('Is Address valid: %r' % is_valid)
        witprog = binascii.unhexlify('701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d')
        witver = 0x00
        hrp = 'bc'
        address = witnessProgram2address(hrp, witver, witprog)
        print('WSH witness address = %s' % address)
        # block hash 0000000000000000000e377cd4083945678ad30c533a8729198bf3b12a8e9315 and tx index 68
        # txn id: ae06fd062b65b7c99dfd3787cb6fa3d46a9c7371e3ca303e0be87fc0e245d775
        witprog_str = '0178ec3c35f8d096f062585deb285d22ab645d83'
        witprog = binascii.unhexlify(witprog_str)
        witver = 0x00
        hrp = 'bc'
        address = witnessProgram2address(hrp, witver, witprog)
        print('Mainnet WPKH witness address = %s for witness program = %s' % (address, witprog_str))
        witver = 0x00
        hrp = 'tb'
        address = witnessProgram2address(hrp, witver, witprog)
        print('Testnet WPKH witness address = %s for witness program = %s' % (address, witprog_str))
        witver = 0x00
        hrp = 'bcrt'
        address = witnessProgram2address(hrp, witver, witprog)
        print('Regtest WPKH witness address = %s for witness program = %s' % (address, witprog_str))
        privkey_hex = 'ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2'
        privkey_wif = privkeyHex2Wif(int(privkey_hex, 16), False, True)
        print('private key in WIF format = %s and in hex = %s' % (privkey_wif, privkey_hex))
        privkey_hex = privkeyWif2Hex(privkey_wif)
        print('private key in WIF format = %s and in hex = %s' % (privkey_wif, privkey_hex))
        address = pubkey2address(binascii.unhexlify('02340886131f76166c8b4fec75b59b23a49a45ea0ffc016eeecd404ae58e0196c0'), "testnet", False)
        print('testnet address = %s' % address)
        privkey_hex = 'bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866'
        privkey_wif = privkeyHex2Wif(int(privkey_hex, 16), True, True)
        print('private key in WIF format = %s and in hex = %s' % (privkey_wif, privkey_hex))
        privkey_hex = '619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9'
        privkey_wif = privkeyHex2Wif(int(privkey_hex, 16), True, True)
        print('private key in WIF format = %s and in hex = %s' % (privkey_wif, privkey_hex))
        print('iAAAAAAAAAA witness_prog = %s' % bytes.decode(binascii.hexlify(hash_utils.hash256(binascii.unhexlify('5202abf78175e80f509269ec5a0359fd43db2ef08bf67a828b7b167f6ceb2efd58c2026b08fbcded824e24cd10e2f688b7989e504c03b9f7a0689f3cea777074979ef402716cfe550eba81a3559573f351b4278d3f0cf1dd019be7047bae0f391e20487c53ae')))))
        address = hash2segwitaddr(hash_utils.hash256(binascii.unhexlify('5202abf78175e80f509269ec5a0359fd43db2ef08bf67a828b7b167f6ceb2efd58c2026b08fbcded824e24cd10e2f688b7989e504c03b9f7a0689f3cea777074979ef402716cfe550eba81a3559573f351b4278d3f0cf1dd019be7047bae0f391e20487c53ae')), nettype="testnet")
        print('P2SH address = %s' % address)
        print('witness prog = %s' % bytes.decode(binascii.hexlify(hash_utils.hash256(binascii.unhexlify('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798ac')))))
        address = hash2segwitaddr(hash_utils.hash256(binascii.unhexlify('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798ac')), nettype="mainnet")
        print('P2SH address = %s' % address)
        address = hash2segwitaddr(hash_utils.hash160(binascii.unhexlify('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')), nettype="mainnet")
        print('P2PKH address = %s' % address)
        address = hash2segwitaddr(binascii.unhexlify('701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d'), nettype="mainnet")
        print('P2WSH address = %s' % address)
        print('Sha256 = %s' % bytes.decode(binascii.hexlify(hashlib.sha256(binascii.unhexlify('52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae')).digest())))
        print('Sha256 = %s' % bytes.decode(binascii.hexlify(hashlib.sha256(binascii.unhexlify('522102980c5de4741f5982f7f453eb730455b8242b209cfd50554906eeba174cbfea9e2102648c69b574c34f1e75709e7cc8edf6ffb9ea24da55a00912baf062893392022721028cae016387a7a560e960b6903dc6b79b17a2fc5731e75482f1b52c88b38cbbf853ae')).digest())))
