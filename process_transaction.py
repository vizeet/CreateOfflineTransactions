import hd_wallet
import json
import pubkey_address
import binascii
import leveldb_parser
from functools import reduce
import hash_utils
import ecdsa

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
        h_s = bytes.decode(binascii.hexlify(h_b))
        #print('hash160 of address = %s' % bytes.decode(binascii.hexlify(h_b)))
        return privkey_wif, pubkey_s, h_s, address_s

# Funding Address is used, returns list of transactions required
def get_utxos_for_address(addresses: list, amount: float):
        utxos = leveldb_parser.getRequiredTxnsForAmountInP2WPKH(addresses, amount)
        return utxos

def get_funding_address_keys():
        access_key_list = jsonobj['Access Key Sources']
        mnemonic_code = ' '.join(jsonobj['Mnemonic Code'])
        keymap_list = []
        for access_key in access_key_list:
                keymap = {}
                keymap['privkey'], keymap['pubkey'], keymap['hash160'], keymap['address'] = get_segwit_address(access_key, mnemonic_code)
                keymap_list.append(keymap)
        return keymap_list

def get_change_address_hash():
        access_key = jsonobj['Access Key Change']
        mnemonic_code = ' '.join(jsonobj['Mnemonic Code'])
        privkey, pubkey, witness_program, address = get_segwit_address(access_key, mnemonic_code)
        witness_program_b = binascii.unhexlify(witness_program)
        return witness_program_b, address

def get_network_fees_satoshis():
        return int(jsonobj['Transaction Fees'] * 10**8)

def get_required_amount():
        input_amount = reduce(lambda x, y: x + y, [tval['Amount'] for tval in jsonobj['Target Info']])
        return input_amount

address_type_prefix_map = {
        'segwit': ['bc1', 'tb1', 'bcrt1'],
        'script': ['3', '2'],
        'pre_segwit': ['1', 'm', 'n']
}

address_type_lock_script_map = {
        'pre_segwit': "OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG",
        'script': "HASH160 <redeem script> EQUAL",
        'segwit': "OP_0 <witness program>"
}

def get_default_script(h: bytes, address_type: str):
        if address_type == 'pre_segwit': # P2PKH
                # OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
                script_b = bytes([0x76, 0xa9, 0x14]) + h + bytes([0x88, 0xac])
        elif address_type == 'segwit': #P2WPKH
                # OP_0 <witness-program>
                script_b = bytes([0x00, 0x14]) + h
        elif address_type == 'script': # P2SH
                # HASH160 <scriptHash> EQUAL
                script_b = bytes([0xa9, 0x14]) + h + bytes([0x87])
        return script_b

def get_address_type(address: str):
        address_type = [k for k, v in address_type_prefix_map.items() if address.startswith(tuple(v))][0]
        return address_type

def get_default_locking_script(address: str):
        address_type = get_address_type(address)
        print('address type = %s' % address_type)
        h_b = pubkey_address.address2hash(address)
        h_s = bytes.decode(binascii.hexlify(h_b))
        print('hash160 of pubkey = %s from address = %s' % (h_s, address))
        script_b = get_default_script(h_b, address_type)
        return script_b
        
def get_locktime():
        return jsonobj['Locktime']

def btc2bytes(btc: float):
        satoshis = int(btc * (10**8))
        hex_b = binascii.unhexlify('%016x' % satoshis)[::-1]
        return hex_b

def locktime2bytes(locktime: int):
        hex_b = binascii.unhexlify('%016x' % locktime)[::-1]
        return hex_b

def prepare_txn_inputs(utxo_list: list):
        input_count = len(utxo_list)
        locktime = get_locktime()
        in_txn = bytes([input_count])
        sequence = None
        for utxo in utxo_list:
                if sequence == None and locktime > 0:
                        sequence = b'\xee\xff\xff\xff'
                else:
                        sequence = b'\xff\xff\xff\xff'
                scriptsig_size = b'\x00' # for bare witness
                in_txn += binascii.unhexlify(utxo['txn_id']) + bytes([utxo['out_index']]) + scriptsig_size + sequence
        in_txn += locktime2bytes(locktime)
        return in_txn

def get_input_satoshis(utxo_list: list):
        input_satoshis = reduce(lambda x,y: x+y, [utxo['value'] for utxo in utxo_list])
        return input_satoshis

def prepare_txn_outs(utxo_list: list, req_amount: float):
        target_count = len(jsonobj['Target Info'])
        out_count = target_count + 1
        input_btc = get_input_satoshis(utxo_list) / (10 ** 8)
        print('input_btc = %.8f' % input_btc)
        change_btc = input_btc - req_amount - jsonobj['Transaction Fees']
        print('change_btc = %.8f' % change_btc)

        out_txn = bytes([out_count])
        for target in jsonobj['Target Info']:
                amount_b = btc2bytes(target['Amount'])
                address = target['Address']
                script_b = get_default_locking_script(address)
                script_size_b = bytes([len(script_b)])
                out_txn += amount_b + script_size_b + script_b
        change_b = btc2bytes(change_btc)
        change_witness_program_b, change_address = get_change_address_hash()
        change_witness_version_b = b'\x00'
        size_change_script_b = bytes([len(change_witness_program_b) + len(change_witness_version_b)])
        out_txn += change_b + size_change_script_b + change_witness_version_b + change_witness_program_b
        return out_txn

def prepare_raw_txn():
        version = b'\x01\x00\x00\x00'
        req_amount = get_required_amount()
        print('required amount = %.8f' % req_amount)
        keymap_list = get_funding_address_keys()
        address_list = [keymap['address'] for keymap in keymap_list]
        print('address_list = %s' % address_list)
        utxo_list = get_utxos_for_address(address_list, req_amount)
        txnin = prepare_txn_inputs(utxo_list)
        print('txnin = %s' % bytes.decode(binascii.hexlify(txnin)))
        txnout = prepare_txn_outs(utxo_list, req_amount)
        print('txnout = %s' % bytes.decode(binascii.hexlify(txnout)))
        locktime = get_locktime()
        locktime_b = locktime2bytes(locktime)
        return version + txnin + txnout + locktime_b

def get_hash_prevouts(utxo_list: list):
        prevouts = b''
        for utxo in utxo_list:
                prevouts += binascii.unhexlify(utxo['txn_id']) + bytes([utxo['out_index']])
        return hash_utils.hash256(prevouts) 

def get_hash_sequence(utxo_list: list):
        concatenated_sequences = b''
        locktime = get_locktime()
        for utxo in utxo_list:
                if sequence == None and locktime > 0:
                        sequence = b'\xee\xff\xff\xff'
                else:
                        sequence = b'\xff\xff\xff\xff'
                concatenated_sequences += sequence
        return hash_utils.hash256(concatenated_sequences) 

def get_hash_outs():
        out_txn = b''
        for target in jsonobj['Target Info']:
                amount_b = btc2bytes(target['Amount'])
                address = target['Address']
                script_b = get_default_locking_script(address)
                script_size_b = bytes([len(script_b)])
                out_txn += amount_b + script_size_b + script_b
        change_b = btc2bytes(change_btc)
        change_witness_program_b, change_address = get_change_address_hash()
        change_witness_version_b = b'\x00'
        size_change_script_b = bytes([len(change_witness_program_b) + len(change_witness_version_b)])
        out_txn += change_b + size_change_script_b + change_witness_version_b + change_witness_program_b
        return hash_utils.hash256(out_txn)

#    nVersion:     01000000
#    hashPrevouts: 96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37
#    hashSequence: 52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b
#    outpoint:     ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000
#    scriptCode:   1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac
#    amount:       0046c32300000000
#    nSequence:    ffffffff
#    hashOutputs:  863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5
#    nLockTime:    11000000
#    nHashType:    01000000
def get_hash_preimage_list():
        locktime = get_locktime()
        locktime_b = locktime2bytes(locktime)
        keymap_list = get_funding_address_keys()
        address_list = [keymap['address'] for keymap in keymap_list]
        req_amount = get_required_amount()
        utxo_list = get_utxos_for_address(address_list, req_amount)
        version = binascii.unhexlify('%08x' % 0x01)[::-1]
        hash_prevouts = get_hash_prevouts(utxo_list)
        hash_sequence = get_hash_sequence(utxo_list)
        hash_outs = get_hash_outs()
        sighash_all = binascii.unhexlify('%08x' % 0x01)[::-1]
        hash_preimage_list = []
        for utxo in utxo_list:
                outpoint = binascii.unhexlify(utxo['txn_id']) + bytes([utxo['out_index']])
                amount_satoshi = utxo['value']
                amount_b = btc2bytes(amount_satoshi / (10 ** 8))
                witness_program = binascii.unhexlify(utxos['hash160'])
                if sequence == None and locktime > 0:
                        sequence = b'\xee\xff\xff\xff'
                else:
                        sequence = b'\xff\xff\xff\xff'
                script = bytes([0x76, 0xa9, len(witness_program)]) + witness_program + bytes([0x88, 0xac])
                script_size_b = bytes([len(script)])
                hash_preimage = version + hash_prevouts + hash_sequence + outpoint + script_size_b + script + amount_b + sequence + hash_outs + locktime_b + sighash_all
                hash_preimage_list.append(hash_preimage)
        return hash_preimage_list

def sign_txn_input():
        for hash_preimage, keymap in zip(get_hash_preimage_list(), get_funding_address_keys()):
                privkey_wif = keymap['privkey']
                pubkey_address.privkeyWif2Hex(privkey_wif)
                SigningKey.from_string(string_private_key, curve=SECP256k1)
        pass

def prepare_signed_txn():
        pass

def process_transaction():
        raw_txn = prepare_raw_txn()
        pass

if __name__ == '__main__':
        #privkey, pubkey, h160, address = get_segwit_address()
        #print('privkey = %s, pubkey = %s, hash160 = %s, address = %s' % (privkey, pubkey, h160, address))
        #utxos = get_utxos_for_address(address, amount = 125)
        #print('utxos = %s' % utxos)
        prepare_raw_txn()
        #get_default_locking_script('1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX')
        #get_default_locking_script('bc1qq3q342clxm2p04hfdknhe3cg6mrs8ur8jfln7h')
