from utils import leveldb_class
import pubkey_address
import binascii

class LevelDBAdapter:
        def __init__(self, nettype: str):
                self.ldb = leveldb_class.LevelDB(nettype = nettype)

        def getRequiredTxnsForAmountInP2WPKH(self, addresses: list, amount: float):
                remaining_amount = amount
                #it = chainstate_db.iterator(include_value=False)
                it = self.ldb.getIteratorChainstateDB()
                required_hash160_b_list = [pubkey_address.address2hash(address) for address in addresses]
                ret_dict = []
                while remaining_amount > 0:
                        try:
                                key = next(it)
                        except StopIteration:
                                break
                        prefix = key[0:1]
                        if prefix == b'C':
                                out_index, pos = leveldb_class.b128_varint_decode(key[33:])
                                txn_hash_big_endian_b = key[1:33]
                                txn_hash_little_endian = bytes.decode(binascii.hexlify(key[1:33][::-1]))
                                jsonobj = self.ldb.getChainstateData(txn_hash_big_endian_b, out_index)
                                if jsonobj['script_type'] == 28 :
                                        size_hash = int(binascii.hexlify(jsonobj['script'][1:2]), 16)
                                        if len(jsonobj['script']) == size_hash + 2:
                                                hash160_b = jsonobj['script'][2:2 + size_hash]
                                                recent_block_hash = self.ldb.getRecentBlockHash()
                                                recent_block_height = self.ldb.getBlockIndex(recent_block_hash)['height']
                                                block_height = jsonobj['height']
                                                block_depth = recent_block_height - block_height
                                                print('block depth = %d' % block_depth)
                                                # coinbase transaction can be redeemed only after 100th confirmation
                                                if (hash160_b in required_hash160_b_list) or (jsonobj['is_coinbase'] == (code & 0x01) and block_depth >= 100):
                                                        witver = 0x00
                                                        #hrp = 'bc'
                                                        hrp = 'bcrt'
                                                        address = pubkey_address.witnessProgram2address(hrp, witver, hash160_b)
                                                        value = jsonobj['amount']
                                                        print('txn_id = %s, out_index = %s, height = %d, hash160 = %s, address = %s, value = %d' % (txn_hash_little_endian, out_index, jsonobj['height'], bytes.decode(binascii.hexlify(hash160_b)), address, value))
                                                        txn_info = {}
                                                        txn_info['txn_id'] = txn_hash_little_endian
                                                        txn_info['out_index'] = out_index
                                                        txn_info['height'] = block_height
                                                        txn_info['hash160'] = bytes.decode(binascii.hexlify(hash160_b))
                                                        txn_info['address'] = address
                                                        txn_info['value'] = value
                                                        ret_dict.append(txn_info)
                                                        remaining_amount = remaining_amount - (value / 100000000)
                return ret_dict


#def iterateChainstateDB():
#        it = chainstate_db.iterator(include_value=False)
#        with open('utxos.txt', 'wt') as utxos_file:
#                while True:
#                        try:
#                                key = next(it)
#                        except StopIteration:
#                                break
#                        prefix = key[0:1]
#                        if prefix == b'C':
#                                out_index, pos = b128_varint_decode(key[33:])
#                                txn_hash_big_endian_b = key[1:33]
#                                txn_hash_big_endian = bytes.decode(binascii.hexlify(txn_hash_big_endian_b))
#                                txn_hash_little_endian = bytes.decode(binascii.hexlify(key[1:33][::-1]))
#                                #print('txn_id_little_endian = %s, out_index = %s' % (txn_hash_little_endian, out_index))
#                                jsonobj = getChainstateData(txn_hash_big_endian_b, out_index)
#                                if jsonobj['script_type'] == 0:
#                                        hash160_b = jsonobj['script'][3:23]
#                                        print('txn_id = %s, out_index = %s, height = %d, script_type = %d, hash160 = %s' % (txn_hash_little_endian, out_index, jsonobj['height'], jsonobj['script_type'], bytes.decode(binascii.hexlify(hash160_b))), file = utxos_file)
#                                elif jsonobj['script_type'] == 1:
#                                        hash160_b = jsonobj['script'][2:22]
#                                        print('txn_id = %s, out_index = %s, height = %d, script_type = %d, hash160 = %s' % (txn_hash_little_endian, out_index, jsonobj['height'], jsonobj['script_type'], bytes.decode(binascii.hexlify(hash160_b))), file = utxos_file)
#                                elif jsonobj['script_type'] in [2, 3]:
#                                        hash256_b = jsonobj['script'][2:34]
#                                        print('txn_id = %s, out_index = %s, height = %d, script_type = %d, hash256 = %s' % (txn_hash_little_endian, out_index, jsonobj['height'], jsonobj['script_type'], bytes.decode(binascii.hexlify(hash256_b))), file = utxos_file)
#                                elif jsonobj['script_type'] in [4, 5]: # script_type = 4 means y is odd and script_type = 5 means y is even in compressed pubkey
#                                        pubkey_b = jsonobj['script'][1:66]
#                                        print('txn_id = %s, out_index = %s, height = %d, script_type = %d, pubkey = %s' % (txn_hash_little_endian, out_index, jsonobj['height'], jsonobj['script_type'], bytes.decode(binascii.hexlify(pubkey_b))), file = utxos_file)
#                                # Bare Witness 
#                                elif jsonobj['script_type'] == 28:
#                                        size_hash = int(binascii.hexlify(jsonobj['script'][1:2]), 16)
#                                        if len(jsonobj['script']) == size_hash + 2:
#                                                hash160_b = jsonobj['script'][2:2 + size_hash]
#                                                print('segwit: txn_id = %s, out_index = %s, height = %d, script_type = %d, hash160 = %s' % (txn_hash_little_endian, out_index, jsonobj['height'], jsonobj['script_type'], bytes.decode(binascii.hexlify(hash160_b))), file = utxos_file)
#                                        else:
#                                                print('txn_id = %s, out_index = %s, height = %d' % (txn_hash_little_endian, out_index, jsonobj['height']), file = utxos_file)
#                                elif jsonobj['script_type'] == 40:
#                                        if len(jsonobj['script']) == size_hash + 2:
#                                                hash256_b = jsonobj['script'][2:2 + size_hash]
#                                                print('segwit: txn_id = %s, out_index = %s, height = %d, script_type = %d, hash256 = %s' % (txn_hash_little_endian, out_index, jsonobj['height'], jsonobj['script_type'], bytes.decode(binascii.hexlify(hash256_b))), file = utxos_file)
#                                        else:
#                                                print('txn_id = %s, out_index = %s, height = %d' % (txn_hash_little_endian, out_index, jsonobj['height']), file = utxos_file)
#                                else:
#                                        print('txn_id = %s, out_index = %s, height = %d' % (txn_hash_little_endian, out_index, jsonobj['height']), file = utxos_file)
#
#def iterateChainstateDBForP2WPKH():
#        it = chainstate_db.iterator(include_value=False)
#        with open('utxos_segwit.txt', 'wt') as utxos_file:
#                while True:
#                        try:
#                                key = next(it)
#                        except StopIteration:
#                                break
#                        prefix = key[0:1]
#                        if prefix == b'C':
#                                out_index, pos = b128_varint_decode(key[33:])
#                                txn_hash_big_endian_b = key[1:33]
#                                txn_hash_little_endian = bytes.decode(binascii.hexlify(key[1:33][::-1]))
#                                jsonobj = getChainstateData(txn_hash_big_endian_b, out_index)
#                                if jsonobj['script_type'] == 28:
#                                        size_hash = int(binascii.hexlify(jsonobj['script'][1:2]), 16)
#                                        if len(jsonobj['script']) == size_hash + 2:
#                                                hash160_b = jsonobj['script'][2:2 + size_hash]
#                                                witver = 0x00
#                                                hrp = 'bc'
#                                                address = pubkey_address.witnessProgram2address(hrp, witver, hash160_b)
#                                                value = jsonobj['amount']
#                                                print('txn_id = %s, out_index = %s, height = %d, hash160 = %s, address = %s, value = %d' % (txn_hash_little_endian, out_index, jsonobj['height'], bytes.decode(binascii.hexlify(hash160_b)), address, value), file = utxos_file)

