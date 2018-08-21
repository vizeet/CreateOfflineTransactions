import hd_wallet
import json
import pubkey_address
import binascii
import leveldb_parser

#my_salt = 'test'
my_salt = ''

jsonobj = json.load(open('transaction_config.json', 'rt'))

def get_segwit_address(access_key: str, mnemonic_code: str):
        #mnemonic_code = ' '.join(jsonobj['Mnemonic Code'])
        print('mnemonic code = %s' % mnemonic_code)
        #access_key = jsonobj['Access Key']
        seed_b = hd_wallet.generateSeedFromStr(mnemonic_code, "mnemonic" + my_salt)
        privkey_i, pubkey_b = hd_wallet.generatePrivkeyPubkeyPair(access_key, seed_b, True)
        privkey_wif = pubkey_address.privkeyHex2Wif(privkey_i, False, True)
        pubkey_s = bytes.decode(binascii.hexlify(pubkey_b))
        address_s = pubkey_address.pubkey2segwitaddr(pubkey_b, 'regtest')
        #address_s = pubkey_address.pubkey2segwitaddr(pubkey_b, 'mainnet')
        h_b = pubkey_address.address2hash(address_s)
        hash160_s = bytes.decode(binascii.hexlify(h_b))
        #print('hash160 of address = %s' % bytes.decode(binascii.hexlify(h_b)))
        return privkey_wif, pubkey_s, hash160_s, address_s

# Funding Address is used, returns list of transactions required
def get_utxos_for_address(addresses: list, amount: float):
        utxos = leveldb_parser.getRequiredTxnsForAmountInP2WPKH(addresses, amount)
        return utxos

def get_funding_address_keys():
        access_key_list = jsonobj['Access Key Source']
        mnemonic_code = jsonobj['Mnemonic Code']
        keymap_list = []
        for access_key in access_key_list:
                keymap = {}
                keymap['privkey'], keymap['pubkey'], keymap['hash160'], keymap['address'] = get_segwit_address(access_key, mnemonic_code)
                keymap_list.append(keymap)

def get_change_address_hash():
        access_key = jsonobj['Access Key Change']
        mnemonic_code = jsonobj['Mnemonic Code']
        privkey, pubkey, h160, address = get_segwit_address(access_key, mnemonic_code)
        return h160, address

def get_required_amount():
        input_amount = reduce(lambda x, y: x + y, [tval['Amount'] for tval in jsonobj['Target Info']])
        return input_amount

address_type_map = {
        "bare_segwit": ['bc1', 'tb1', 'bcrt1'],
        "script": ['3', '2'],
        'pre_segwit': ['1', 'm', 'n']
}

def get_default_locking_script(address: str):
        address_type = reduce(address.startswith(), 
        address_type = ''
        if address[0:3] in ['bc1', 'tb1'] or address[0:5] == 'bcrt1':
                address_type = 'bare_segwit'
        elif address[0] in ['3', '2']:
                address_type = 'script'
        elif address[0] in ['1', '3', '2']:
                address_type = 'pre_segwit'
        else:
                raise ValueError
        return address_type

def get_locktime = lambda: jsonobj['Locktime']

def btc2bytes(btc: float):
        satoshis = int(btc * (10**8))
        hex_b = binascii.unhexlify('%016x' % satoshis)[::-1]
        return hex_b

def locktime2bytes(locktime: int):
        hex_b = binascii.unhexlify('%016x' % locktime)[::-1]
        return hex_b

def get_txn_inputs(utxo_list: list):
        input_count = len(utxo_list)
        locktime = get_locktime()
        in_txn = bytes([input_count])
        for utxo in utxo_list:
                if sequence = None and locktime > 0:
                        sequence = b'\xee\xff\xff\xff'
                else:
                        sequence = b'\xff\xff\xff\xff'
                scriptsig_size = b'\x00' # for bare witness
                in_txn += bytes.decode(binascii.hexlify(utxo['txn_id'])) + bytes([utxo['out_index']]) + scriptsig_size + sequence
        in_txn += locktime2bytes(locktime)
        return in_txn

def get_input_satoshis(utxos: list):
        input_satoshis = reduce(lambda x,y: x+y, [utxo['value'] for utxo in utxos])
        return input_satoshis

def get_txn_outs(utxos: list):
        out_count = len(jsonobj['Target Info']) + 1
        
        change = get_input_satoshis(utxos)

def prepare_raw_txn():
        version = b'\x01\x00\x00\x00'
        req_amount = get_required_amount()
        keymap_list = get_funding_address_keys():
        address_list = [keymap['address'] for keymap in keymap_list]
        utxos = get_utxos_for_address(address_list, req_amount)
        txin = get_txn_inputs(utxos)
        

def sign_txn_input():
        pass

def prepare_signed_txn():
        pass

def process_transaction():
        #
        pass

if __name__ == '__main__':
        privkey, pubkey, h160, address = get_segwit_address()
        print('privkey = %s, pubkey = %s, hash160 = %s, address = %s' % (privkey, pubkey, h160, address))
        #utxos = get_utxos_for_address(address, amount = 125)
        #print('utxos = %s' % utxos)
