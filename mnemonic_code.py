import hashlib
from utils import random_number_generator
import binascii
from functools import reduce
import math

def getChecksumBitCount(mnemonic_length: int):
        if (mnemonic_length % 3) != 0:
                raise ValueError('Invalid Mnemonic code length')
        checksum_bit_count = mnemonic_length // 3
        return checksum_bit_count

def getEntropyBitCount(mnemonic_length: int):
        if (mnemonic_length % 3) != 0:
                raise ValueError('Invalid Mnemonic code length')
        entropy_bit_count = (mnemonic_length * 32) // 3
        return entropy_bit_count

def getCheckEntropyBitCount(mnemonic_length: int):
        checksum_bit_count = getChecksumBitCount(mnemonic_length)
        entropy_bit_count = getEntropyBitCount(mnemonic_length)
        entropy_checksum_bit_count = entropy_bit_count + checksum_bit_count
        return entropy_checksum_bit_count

def getEntropyCheckBits(mnemonic_length: int):
        entropy_bit_count = getEntropyBitCount(mnemonic_length)
        print('entropy_bit_count = %d' % entropy_bit_count)
        random_number_b = random_number_generator.getRandomNumberBits(entropy_bit_count)
        print('random_number = %s' % bytes.decode(binascii.hexlify(random_number_b)))
        checksum_bit_count = getChecksumBitCount(mnemonic_length)
        print('checksum bit count = %d' % checksum_bit_count)
        checksum = int(binascii.hexlify(hashlib.sha256(random_number_b).digest()), 16)
        print('checksum = %x' % checksum)
        initial_checksum = checksum >> (256 - checksum_bit_count)
        random_number = int(bytes.decode(binascii.hexlify(random_number_b)), 16)
        shifted_random_number = random_number << checksum_bit_count
        entropy_check_i = shifted_random_number | initial_checksum
        entropy_check_size_bytes = math.ceil((entropy_bit_count + checksum_bit_count) / 8)
        print('entropy_check_size_bytes = %d' % entropy_check_size_bytes)
        entropy_check_s = ('%x' % entropy_check_i).zfill(entropy_check_size_bytes * 2)
        print('entropy_check_s = %s' % entropy_check_s)
        entropy_check_b = binascii.unhexlify(entropy_check_s)
        return entropy_check_b

def getMnemonicWordList():
        word_list = []
        with open('utils/mnemonic_word_list_english.txt', 'rt') as word_file:
                word_list = word_file.read().splitlines()
        return word_list

def entropyCheckBits2List(entropy_check_b: bytes, size: int):
        selector_int = int(binascii.hexlify(entropy_check_b), 16)
        selector_list = []
        while size >= 11:
                selector_list.append(selector_int & 0x07FF)
                selector_int = selector_int >> 11
                size -= 11
        print('len of selector list = %d' % len(selector_list))
        return selector_list[::-1]

def getEntropyCheckBitCountFromSelectorCount(selector_count: int):
        return selector_count * 11

def getChecksumBitCountFromEntropyBitCount(entropy_bit_count: int):
        return entropy_bit_count // 32

def convertSelectorList2Bits(selector_list: list):
        entropy_check_bit_count = getEntropyCheckBitCountFromSelectorCount(len(selector_list))
        print('entropy checksum bit count = %d' % entropy_check_bit_count)
        entropy_check_i = reduce(lambda x, y: (x << 11) | y, selector_list)
        print('entropy_check_i = %x' % entropy_check_i)
        return entropy_check_i

def getMnemonicWordCodeString(mnemonic_length: int):
        word_list = getMnemonicWordList()
        entropy_check_bit_count = getCheckEntropyBitCount(mnemonic_length)
        print('entropy check bit count = %d' % entropy_check_bit_count)
        entropy_check_b = getEntropyCheckBits(mnemonic_length)
        print('entropy check = %s' % bytes.decode(binascii.hexlify(entropy_check_b)))
        selector_list = entropyCheckBits2List(entropy_check_b, entropy_check_bit_count)
        mnemonic_word_list = getMnemonicWordList()
        word_key_list = [mnemonic_word_list[selector] for selector in selector_list]

        return ' '.join(word_key_list)

def verifyChecksumInSelectorBits(entropy_check_i: int, mnemonic_length: int):
        entropy_bit_count = getEntropyBitCount(mnemonic_length)
        checksum_bit_count = getChecksumBitCount(mnemonic_length)
        entropy_i = (entropy_check_i >> checksum_bit_count)
        entropy_size_bytes = entropy_bit_count // 8
        print('entropy_size_bytes = %d' % entropy_size_bytes)
        entropy_s = ('%x' % entropy_i).zfill(entropy_size_bytes * 2)
        print('entropy_s = %s' % entropy_s)
        entropy_b = binascii.unhexlify(entropy_s)
        set_bits = (1 << checksum_bit_count) - 1
        initial_checksum = entropy_check_i & set_bits
        print('initial_checksum = %x' % initial_checksum)
        checksum_calculated = int(bytes.decode(binascii.hexlify(hashlib.sha256(entropy_b).digest())), 16)
        print('checksum_calculated = %x' % checksum_calculated)
        initial_checksum_calculated = (checksum_calculated >> (256 - checksum_bit_count))
        print('initial_checksum_calculated = %x' % initial_checksum_calculated)
        return (initial_checksum_calculated == initial_checksum)

def verifyMnemonicWordCodeString(mnemonic_code: str):
        word_key_list = mnemonic_code.split()
        mnemonic_length = len(word_key_list)
        mnemonic_word_list = getMnemonicWordList()
        selector_list = [mnemonic_word_list.index(word) for word in word_key_list]
        entropy_check_i = convertSelectorList2Bits(selector_list)
        print('entropy_check_i = %x' % entropy_check_i)
        return verifyChecksumInSelectorBits(entropy_check_i, mnemonic_length)

if __name__ == '__main__':
        word_key_list = getMnemonicWordCodeString(15)

        print('mnemonic key list = %s' % word_key_list)

        print('is valid = %r' % verifyMnemonicWordCodeString(word_key_list))
