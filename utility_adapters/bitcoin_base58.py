from utils import base58
import binascii
from functools import reduce

g_base58_prefixes = {
        "mainnet": {
                "PKH": 0x00,
                "SH": 0x05,
                "WIF_Uncompressed": 0x80,
                "WIF_Compressed": 0x80,
                "BIP32_Pubkey": 0x0488B21E,
                "BIP32_Privkey": 0x0488ADE4
        },
        "testnet": {
                "PKH": 0x6F,
                "SH": 0xC4,
                "WIF_Uncompressed": 0xEF,
                "WIF_Compressed": 0xEF,
                "BIP32_Pubkey": 0x043587CF,
                "BIP32_Privkey": 0x04358394
        },
        "regtest": {
                "PKH": 0x6F,
                "SH": 0xC4,
                "WIF_Uncompressed": 0xEF,
                "WIF_Compressed": 0xEF,
                "BIP32_Pubkey": 0x043587CF,
                "BIP32_Privkey": 0x04358394
        }
}

g_address_prefixes = {
        "mainnet": {
                "PKH": "1",
                "SH": "3",
                "WIF_Uncompressed": "5",
                "WIF_Compressed": ["K", "L"],
                "BIP32_Pubkey": 0x0488B21E,
                "BIP32_Privkey": 0x0488ADE4
        },
        "testnet": {
                "PKH": ["m", "n"],
                "SH": "2",
                "WIF_Uncompressed": "9",
                "WIF_Compressed": "c",
                "BIP32_Pubkey": 0x043587CF,
                "BIP32_Privkey": 0x04358394
        },
        "regtest": {
                "PKH": ["m", "n"],
                "SH": "2",
                "WIF_Uncompressed": "9",
                "WIF_Compressed": "c",
                "BIP32_Pubkey": 0x043587CF,
                "BIP32_Privkey": 0x04358394
        }
}

g_nettypes = [k for k, v in g_address_prefixes.items()]

#address_prefixes_for_wif_compressed = ['K', 'L', 'c']
def get_address_prefixes_for_wif_compressed():
        global g_address_prefixes

        wif_compressed = list(set(reduce(lambda x,y: list(set(x + y)), [value['WIF_Compressed'] if type(value['WIF_Compressed']) == list else [value['WIF_Compressed']] for key, value in g_address_prefixes.items()])))

        return wif_compressed

g_address_prefixes_for_wif_compressed = get_address_prefixes_for_wif_compressed()

#address_prefixes_for_wif_uncompressed = ['9', '5']
def get_address_prefixes_for_wif_uncompressed():
        global g_address_prefixes

        wif_uncompressed = list(set(reduce(lambda x,y: list(set(x + y)), [value['WIF_Uncompressed'] if type(value['WIF_Uncompressed']) == list else [value['WIF_Uncompressed']] for key, value in g_address_prefixes.items()])))

        return wif_uncompressed

g_address_prefixes_for_wif_uncompressed = get_address_prefixes_for_wif_uncompressed()

#address_prefixes_for_wif = ['9', '5', 'K', 'L', 'c']
def get_address_prefixes_for_wif():
        global g_address_prefixes_for_wif_compressed, g_address_prefixes_for_wif_uncompressed

        x = g_address_prefixes_for_wif_compressed
        y = g_address_prefixes_for_wif_uncompressed
        return x + y
        
g_address_prefixes_for_wif = get_address_prefixes_for_wif()

#g_address_prefixes_nettype_for_wif = {'mainnet': ['5', 'K', 'L'], 'testnet': ['9', 'c']}
def get_address_prefixes_nettype_for_wif():
        global g_address_prefixes

        ap = {}
        a = g_address_prefixes['mainnet']['WIF_Compressed']
        a = a if type(a) == list else [a]
        b = g_address_prefixes['mainnet']['WIF_Uncompressed']
        b = b if type(b) == list else [b]
        ap['mainnet'] = a + b

        a = g_address_prefixes['testnet']['WIF_Compressed']
        a = a if type(a) == list else [a]
        b = g_address_prefixes['testnet']['WIF_Uncompressed']
        b = b if type(b) == list else [b]
        ap['testnet'] = a + b

        return ap

g_address_prefixes_nettype_for_wif = get_address_prefixes_nettype_for_wif()

def forAddress(h: bytes, nettype: str, is_script: bool):
        global g_base58_prefixes

        prefix = g_base58_prefixes[("mainnet", "testnet")[nettype != 'mainnet']][("PKH", "SH")[is_script == True]]
        print('address prefix before encoding = %02x' % prefix)
        address = base58.base58checkEncode(binascii.unhexlify('%02x' % prefix), h)
        return address

def addressVerify(address: str):
        prefix = address[0:1]
        is_valid = base58.base58checkVerify(prefix, address)
        return is_valid

def wifVerify(wif: str):
        wif_prefix = wif[0:2]
        is_valid = base58.base58checkVerify(wif_prefix, wif)
        return is_valid

def encodeWifPrivkey(h: int, nettype: str, for_compressed_pubkey: bool):
        global g_base58_prefixes

        prefix = g_base58_prefixes[("mainnet", "testnet")[nettype != 'mainnet']][("WIF_Uncompressed", "WIF_Compressed")[for_compressed_pubkey == True]]
        print('wif prefix before encoding = %02x' % prefix)
        h_b = binascii.unhexlify('%064x' % h)
        if for_compressed_pubkey == True:
                h_b = h_b + b'\01'
        wif_encoded = base58.base58checkEncode(binascii.unhexlify('%02x' % prefix), h_b)
        return wif_encoded

def base58checkDecode(s: str):
        with_checksum_int = base58.base58_decode(s)
        with_checksum_b = binascii.unhexlify('%x' % with_checksum_int)
        decode_b = with_checksum_b[1:-4]
        return decode_b

def decodeWifPrivkey(privkey_wif: str):
        global g_address_prefixes_nettype_for_wif
        prefix = privkey_wif[0:1]
        wif_decoded_b = base58checkDecode(privkey_wif)
        nettype = [k for k, v in g_address_prefixes_nettype_for_wif.items() if prefix in v][0]

        if prefix not in g_address_prefixes_for_wif:
                print('invalid prefix = %s' % prefix)
                exit()

        for_compressed_pubkey = (prefix in g_address_prefixes_for_wif_compressed)

#        if for_compressed_pubkey == True:
#                wif_decoded = bytes.decode(binascii.hexlify(wif_decoded_b[:-1]))
#        else:
        wif_decoded = bytes.decode(binascii.hexlify(wif_decoded_b))
        
        return nettype, prefix, wif_decoded, for_compressed_pubkey

if __name__ == '__main__':
        #hash160_b = address2hash160('19WeyGVVqPuYJR2dpVUR6d8dn1SafrNKyS')
        #print('hash 160 = %s' % bytes.decode(binascii.hexlify(hash160_b)))
        nettype, prefix, wif_decoded, for_compressed_pubkey = decodeWifPrivkey('5JWp4FM7sfAAE88DW3yvGF5mQyrsEXeWzXZn79bg61Vg8YMfJjA')
        print('nettype = %s, prefix = %s, wif_decoded = %s, for_compressed_pubkey = %s' % (nettype, prefix, wif_decoded, for_compressed_pubkey))
        nettype, prefix, wif_decoded, for_compressed_pubkey = decodeWifPrivkey('L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ')
        print('nettype = %s, prefix = %s, wif_decoded = %s, for_compressed_pubkey = %s' % (nettype, prefix, wif_decoded, for_compressed_pubkey))
        print('address_prefixes_for_wif = %s' % g_address_prefixes_for_wif)
        print('address_prefixes_nettype_for_wif = %s' % g_address_prefixes_nettype_for_wif)
