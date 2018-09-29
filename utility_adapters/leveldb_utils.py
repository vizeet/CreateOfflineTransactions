from utils import leveldb_class
import pubkey_address
import binascii

class LevelDBAdapter:
        def __init__(self, nettype: str):
                self.nettype = nettype
                self.ldb = leveldb_class.LevelDB(nettype = nettype)

        def getRequiredTxnsForAmountInP2PKH(self, addresses: list, amount: float):
                remaining_amount = amount
                #it = chainstate_db.iterator(include_value=False)
                it = self.ldb.getIteratorChainstateDB()
                required_hash160_b_list = [pubkey_address.address2hash(address) for address in addresses]
                for required_h160 in required_hash160_b_list:
                        print('YYYYYY required_h160 = %s' % (bytes.decode(binascii.hexlify(required_h160))))
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
                                if jsonobj['script_type'] == 0 :
                                        size_hash = int(binascii.hexlify(jsonobj['script'][2:3]), 16)
                                        print('JJJJJJJJJJJJJ script = %s' % bytes.decode(binascii.hexlify(jsonobj['script'])))
                                        hash160_b = jsonobj['script'][3:3 + size_hash]
                                        recent_block_hash = self.ldb.getRecentBlockHash()
                                        recent_block_height = self.ldb.getBlockIndex(recent_block_hash)['height']
                                        block_height = jsonobj['height']
                                        block_depth = recent_block_height - block_height
                                        print('block depth = %d' % block_depth)
                                        # coinbase transaction can be redeemed only after 100th confirmation
                                        if (hash160_b in required_hash160_b_list and jsonobj['is_coinbase'] == False) or (hash160_b in required_hash160_b_list and jsonobj['is_coinbase'] == True and block_depth >= 100):
                                                address = pubkey_address.pkh2address(hash160_b, self.nettype)
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

        def getRequiredTxnsForAmountInP2WSH(self, addresses: list, amount: float):
                remaining_amount = amount
                it = self.ldb.getIteratorChainstateDB()
                required_sha256_b_list = [pubkey_address.address2hash(address) for address in addresses]
                for required_sha256 in required_sha256_b_list:
                        print('YYYYYY required_sha256 = %s' % (bytes.decode(binascii.hexlify(required_sha256))))
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
                                if jsonobj['script_type'] == 40 :
                                        size_hash = int(binascii.hexlify(jsonobj['script'][1:2]), 16)
                                        if len(jsonobj['script']) == size_hash + 2:
                                                sha256_b = jsonobj['script'][2:2 + size_hash]
                                                recent_block_hash = self.ldb.getRecentBlockHash()
                                                recent_block_height = self.ldb.getBlockIndex(recent_block_hash)['height']
                                                block_height = jsonobj['height']
                                                block_depth = recent_block_height - block_height
                                                print('block depth = %d' % block_depth)
                                                # coinbase transaction can be redeemed only after 100th confirmation
                                                if (sha256_b in required_sha256_b_list and jsonobj['is_coinbase'] == False) or (sha256_b in required_sha256_b_list and jsonobj['is_coinbase'] == True and block_depth >= 100):
                                                        witver = 0x00
                                                        #hrp = 'bc'
                                                        hrp = 'bcrt'
                                                        address = pubkey_address.witnessProgram2address(hrp, witver, sha256_b)
                                                        value = jsonobj['amount']
                                                        print('txn_id = %s, out_index = %s, height = %d, sha256 = %s, address = %s, value = %d' % (txn_hash_little_endian, out_index, jsonobj['height'], bytes.decode(binascii.hexlify(sha256_b)), address, value))
                                                        txn_info = {}
                                                        txn_info['txn_id'] = txn_hash_little_endian
                                                        txn_info['out_index'] = out_index
                                                        txn_info['height'] = block_height
                                                        txn_info['sha256'] = bytes.decode(binascii.hexlify(sha256_b))
                                                        txn_info['address'] = address
                                                        txn_info['value'] = value
                                                        ret_dict.append(txn_info)
                                                        remaining_amount = remaining_amount - (value / 100000000)
                return ret_dict

        def getRequiredTxnsForAmountInP2WPKH(self, addresses: list, amount: float):
                remaining_amount = amount
                #it = chainstate_db.iterator(include_value=False)
                it = self.ldb.getIteratorChainstateDB()
                required_hash160_b_list = [pubkey_address.address2hash(address) for address in addresses]
                for required_h160 in required_hash160_b_list:
                        print('YYYYYY required_h160 = %s' % (bytes.decode(binascii.hexlify(required_h160))))
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
                                                if (hash160_b in required_hash160_b_list and jsonobj['is_coinbase'] == False) or (hash160_b in required_hash160_b_list and jsonobj['is_coinbase'] == True and block_depth >= 100):
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

        def getRequiredTxnsForAmountInP2SH(self, addresses: list, amount: float):
                remaining_amount = amount
                #it = chainstate_db.iterator(include_value=False)
                it = self.ldb.getIteratorChainstateDB()
                required_hash160_b_list = [pubkey_address.address2hash(address) for address in addresses]
                for required_h160 in required_hash160_b_list:
                        print('IIIIIII required_h160 = %s' % (bytes.decode(binascii.hexlify(required_h160))))
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
                                if jsonobj['script_type'] == 1 :
                                        size_hash = int(binascii.hexlify(jsonobj['script'][1:2]), 16)
                                        hash160_b = jsonobj['script'][2:2 + size_hash]
                                        print('IIIIIIIIIII hash160 = %s' % bytes.decode(binascii.hexlify(hash160_b)))
                                        recent_block_hash = self.ldb.getRecentBlockHash()
                                        recent_block_height = self.ldb.getBlockIndex(recent_block_hash)['height']
                                        block_height = jsonobj['height']
                                        block_depth = recent_block_height - block_height
                                        print('block depth = %d' % block_depth)
                                        # coinbase transaction can be redeemed only after 100th confirmation
                                        if (hash160_b in required_hash160_b_list and jsonobj['is_coinbase'] == False) or (hash160_b in required_hash160_b_list and jsonobj['is_coinbase'] == True and block_depth >= 100):
                                                address = pubkey_address.sh2address(hash160_b, self.nettype)
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


        def iterateChainstateDB(self):
                #it = chainstate_db.iterator(include_value=False)
                it = self.ldb.getIteratorChainstateDB()
                with open('utxos.txt', 'wt') as utxos_file:
                        while True:
                                try:
                                        key = next(it)
                                except StopIteration:
                                        break
                                prefix = key[0:1]
                                if prefix == b'C':
                                        out_index, pos = leveldb_class.b128_varint_decode(key[33:])
                                        txn_hash_big_endian_b = key[1:33]
                                        txn_hash_big_endian = bytes.decode(binascii.hexlify(txn_hash_big_endian_b))
                                        txn_hash_little_endian = bytes.decode(binascii.hexlify(key[1:33][::-1]))
                                        #print('txn_id_little_endian = %s, out_index = %s' % (txn_hash_little_endian, out_index))
                                        jsonobj = self.ldb.getChainstateData(txn_hash_big_endian_b, out_index)
                                        if jsonobj['script_type'] == 0:
                                                hash160_b = jsonobj['script'][3:23]
                                                print('txn_id = %s, out_index = %s, height = %d, script_type = %d, hash160 = %s' % (txn_hash_little_endian, out_index, jsonobj['height'], jsonobj['script_type'], bytes.decode(binascii.hexlify(hash160_b))), file = utxos_file)
                                        elif jsonobj['script_type'] == 1:
                                                hash160_b = jsonobj['script'][2:22]
                                                print('txn_id = %s, out_index = %s, height = %d, script_type = %d, hash160 = %s, script = %s' % (txn_hash_little_endian, out_index, jsonobj['height'], jsonobj['script_type'], bytes.decode(binascii.hexlify(hash160_b)), bytes.decode(binascii.hexlify(jsonobj['script']))), file = utxos_file)
                                        elif jsonobj['script_type'] in [2, 3]:
                                                hash256_b = jsonobj['script'][2:34]
                                                print('txn_id = %s, out_index = %s, height = %d, script_type = %d, hash256 = %s' % (txn_hash_little_endian, out_index, jsonobj['height'], jsonobj['script_type'], bytes.decode(binascii.hexlify(hash256_b))), file = utxos_file)
                                        elif jsonobj['script_type'] in [4, 5]: # script_type = 4 means y is odd and script_type = 5 means y is even in compressed pubkey
                                                pubkey_b = jsonobj['script'][1:66]
                                                print('txn_id = %s, out_index = %s, height = %d, script_type = %d, pubkey = %s' % (txn_hash_little_endian, out_index, jsonobj['height'], jsonobj['script_type'], bytes.decode(binascii.hexlify(pubkey_b))), file = utxos_file)
                                        # Bare Witness 
                                        elif jsonobj['script_type'] == 28:
                                                size_hash = int(binascii.hexlify(jsonobj['script'][1:2]), 16)
                                                if len(jsonobj['script']) == size_hash + 2:
                                                        hash160_b = jsonobj['script'][2:2 + size_hash]
                                                        print('segwit: txn_id = %s, out_index = %s, height = %d, script_type = %d, hash160 = %s' % (txn_hash_little_endian, out_index, jsonobj['height'], jsonobj['script_type'], bytes.decode(binascii.hexlify(hash160_b))), file = utxos_file)
                                                else:
                                                        print('txn_id = %s, out_index = %s, height = %d' % (txn_hash_little_endian, out_index, jsonobj['height']), file = utxos_file)
                                        elif jsonobj['script_type'] == 40:
                                                if len(jsonobj['script']) == size_hash + 2:
                                                        hash256_b = jsonobj['script'][2:2 + size_hash]
                                                        print('segwit: txn_id = %s, out_index = %s, height = %d, script_type = %d, hash256 = %s' % (txn_hash_little_endian, out_index, jsonobj['height'], jsonobj['script_type'], bytes.decode(binascii.hexlify(hash256_b))), file = utxos_file)
                                                else:
                                                        print('txn_id = %s, out_index = %s, height = %d' % (txn_hash_little_endian, out_index, jsonobj['height']), file = utxos_file)
                                        else:
                                                print('txn_id = %s, out_index = %s, height = %d, script_type = %s' % (txn_hash_little_endian, out_index, jsonobj['height'], jsonobj['script_type']), file = utxos_file)

        def iterateChainstateDBForP2WSH(self):
                it = self.ldb.getIteratorChainstateDB()
                #it = chainstate_db.iterator(include_value=False)
                with open('utxos_segwit.txt', 'wt') as utxos_file:
                        while True:
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
                                        if jsonobj['script_type'] == 40:
                                                size_hash = int(binascii.hexlify(jsonobj['script'][1:2]), 16)
                                                if len(jsonobj['script']) == size_hash + 2:
                                                        hash160_b = jsonobj['script'][2:2 + size_hash]
                                                        witver = 0x00
                                                        hrp = 'bc'
                                                        address = pubkey_address.witnessProgram2address(hrp, witver, hash160_b)
                                                        value = jsonobj['amount']
                                                        print('txn_id = %s, out_index = %s, height = %d, hash160 = %s, address = %s, value = %d, type = %d' % (txn_hash_little_endian, out_index, jsonobj['height'], bytes.decode(binascii.hexlify(hash160_b)), address, value, jsonobj['script_type']), file = utxos_file)

if __name__ == '__main__':
        ldb = LevelDBAdapter('mainnet')
        ldb.iterateChainstateDBForP2WSH()
        #ldb.iterateChainstateDB()
        #jsobobj = ldb.getRequiredTxnsForAmountInP2SH('2MxsKZXkDiaJw5LbHyzNGBGksM42MF7GXMh', 150)
        #print('jsonobj = %s' % jsonobj)
