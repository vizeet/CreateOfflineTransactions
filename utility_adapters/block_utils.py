def encode_var_length_bytes(length: int):
        if length < 0xfd:
                return bytes([length])
        if length < 0xffff:
                return b'\xfd' + (length).to_bytes(2, byteorder="little")
        if length < 0xffffffff:
                return b'\xfe' + (length).to_bytes(4, byteorder="little")
        if length < 0xffffffffffffffff:
                return b'\xff' + (length).to_bytes(8, byteorder="little")
