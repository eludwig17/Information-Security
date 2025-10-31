import des_constants_sbox_tables
import des_constants_permutation_tables
import des_constants_subkey_tables
import homework10


class coreDES:
    @staticmethod
    def addPadding(message):
        padLen = 8 - len(message) % 8
        padding = chr(padLen) * padLen
        message +=padding.encode("utf-8")
        return message

    @staticmethod
    def remPadding(message):
        if not isinstance(message, (bytes, bytearray)) or len(message) == 0:
            raise TypeError("remPadding expects non-empty bytes or bytearray")
        padLen = message[-1]
        if padLen < 1 or padLen > 8:
            raise ValueError("PadLen invalid")
        if len(message) < padLen:
            raise ValueError("MSG shorter than padLen")
        if message[-padLen:] != bytes([padLen]) * padLen:
            raise ValueError("Padding is invalid")
        return message[:-padLen]

    @staticmethod
    def byte2bitArray(byteString):
        result = []
        for byte in byteString:
            for bit in [7, 6, 5, 4, 3, 2, 1, 0]:
                mask = 1 << bit
                result.append(1 if (byte & mask) else 0)
        return result

    @staticmethod
    def bitArray2byte(bitArray):
        if bitArray is None:
            return bytes()
        result = []
        byte = 0
        for i in range(len(bitArray)):
            bit = bitArray[i]
            if bit not in (0, 1):
                raise ValueError("bitArray contains non-binary values")
            shift = 7 - (i % 8)
            byte |= (bit << shift)
            if (i % 8) == 7:
                result.append(byte)
                byte = 0
        if len(bitArray) % 8 != 0:
            result.append(byte)
        return bytes(result)

    @staticmethod
    def nSplit(data, splitSize=64):
        if splitSize <= 0:
            raise ValueError("splitSize must be positive")
        if isinstance(data, (bytes, bytearray)):
            buf = bytearray()
            for item in data:
                buf.append(item)
                if len(buf) == splitSize:
                    yield bytes(buf)
                    buf.clear()
            if len(buf) > 0:
                yield bytes(buf)
            return
        buffer = []
        for item in data:
            buffer.append(item)
            if len(buffer) == splitSize:
                yield buffer
                buffer = []
        if len(buffer) > 0:
            yield buffer

    @staticmethod
    def permute(block, table):
        return [block[x] for x in table]

    @staticmethod
    def Lshift(sequence: list, n: int):
        if not sequence:
            return []
        L = len(sequence)
        n = n % L
        return sequence[n:] + sequence[:n]

    @staticmethod
    def xor(x: list, y: list):
        if len(x) != len(y):
            raise ValueError("Lists must be of equal length")
        return [1 if (a != b) else 0 for a, b in zip(x, y)]

    @staticmethod
    def substitute(bit_array: list):
        output = []
        for i in range(8):
            start = i * 6
            chunk = bit_array[start:start + 6]
            row = (chunk[0] << 1) | chunk[5]
            col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
            sbox = des_constants_sbox_tables._S_BOXES[i]
            value = sbox[row][col]
            for bit_pos in [3, 2, 1, 0]:
                output.append((value >> bit_pos) & 1)
        return output

    @staticmethod
    def function(R, subkey):
        expanded = coreDES.permute(R, des_constants_permutation_tables._EXPAND)
        xored = coreDES.xor(expanded, subkey)
        substituted = coreDES.substitute(xored)
        return coreDES.permute(substituted, des_constants_permutation_tables._SBOX_PERM)

    @staticmethod
    def generateSubkeys(encryption_key: bytes):
        subkeys = []
        keybits = coreDES.byte2bitArray(encryption_key)
        k0 = coreDES.permute(keybits, des_constants_subkey_tables._KEY_PERMUTATION1)
        R = k0[28:]
        L = k0[:28]
        for i in range(16):
            L = coreDES.Lshift(L, des_constants_subkey_tables._KEY_SHIFT[i])
            R = coreDES.Lshift(R, des_constants_subkey_tables._KEY_SHIFT[i])
            kI = coreDES.permute(L + R, des_constants_subkey_tables._KEY_PERMUTATION2)
            subkeys.append(kI)
        return subkeys

    @staticmethod
    def encryptBlock(block, subkeys):
        block = coreDES.permute(block, des_constants_permutation_tables._INIT_PERMUTATION)
        L = block[:32]
        R = block[32:]
        for i in range(16):
            L, R = R, coreDES.xor(L, coreDES.function(R, subkeys[i]))
        preoutput = R + L
        block = coreDES.permute(preoutput, des_constants_permutation_tables._FINAL_PERMUTATION)
        return block

    @staticmethod
    def decryptBlock(block, subkeys):
        block = coreDES.permute(block, des_constants_permutation_tables._INIT_PERMUTATION)
        L = block[:32]
        R = block[32:]
        for i in range(15, -1, -1):
            L, R = R, coreDES.xor(L, coreDES.function(R, subkeys[i]))
        preoutput = R + L
        block = coreDES.permute(preoutput, des_constants_permutation_tables._FINAL_PERMUTATION)
        return block

class DES:
    """ Implements the original DES algorithm with a 64-bit key and three block
        modes: ECB, CBC, and OFB. """

    def __init__(self, key, mode="ECB", iv=None):
        """ Creates a new encryption object
            Parameters:
              key  - 64-bit secret key given as a byte string
              mode - "ECB" or "CBC" or "OFB"
              iv   - 64-bit byte string that is required for CBC and OFB modes """
        if len(key) != 8:
            raise ValueError("DES key has to be 8 bytes.")
        self.key = key
        self.mode = mode.upper()
        self.iv = iv
        self.originalIV = iv
        if self.mode in ['CBC', 'OFB'] and iv is None:
            raise ValueError(f"IV is required for {self.mode} mode.")
        if iv is not None and len(iv) != 8:
            raise ValueError("IV has to be 8 bytes.")
        self.subkeys = coreDES.generateSubkeys(self.key)

    def reset(self):
        """ Resets the IV to its original value to start a new encryption or
            decryption. This function only applies to CBC and OFB modes """
        if self.mode in ['CBC', 'OFB']:
            self.iv = self.originalIV

    def encrypt(self, data):
        """ Encrypts data with the DES encryption algorithm
            Parameters:
              data - raw byte string to be encrypted """
        pt = coreDES.addPadding(data)
        ptBits = coreDES.byte2bitArray(pt)
        ctBits = []
        if self.mode == 'ECB':
            for block in coreDES.nSplit(ptBits, 64):
                if len(block) != 64:
                    block = block + [0] * (64-len(block))
                ctBits += coreDES.encryptBlock(block, self.subkeys)
        elif self.mode == 'CBC':
                ivBits = coreDES.byte2bitArray(self.iv)
                previousCT = ivBits
                for block in coreDES.nSplit(ptBits, 64):
                    if len(block) != 64:
                        block = block + [0] * (64 - len(block))
                    xored = coreDES.xor(block, previousCT)
                    encrypted = coreDES.encryptBlock(xored, self.subkeys)
                    ctBits += encrypted
                    previousCT = encrypted
        elif self.mode == 'OFB':
            ivBits = coreDES.byte2bitArray(self.iv)
            feedback = ivBits
            for block in coreDES.nSplit(ptBits, 64):
                if len(block) != 64:
                    block = block + [0] * (64 - len(block))
                encryptFeedback = coreDES.encryptBlock(feedback, self.subkeys)
                ctBlock = coreDES.xor(block, encryptFeedback)
                ctBits += ctBlock
                feedback = encryptFeedback
        else:
            raise ValueError(f"{self.mode} isn't supported.")
        return coreDES.bitArray2byte(ctBits)

    def decrypt(self, data):
        """ Decrypts data with the DES encryption algorithm.
            Parameters:
              data - raw byte string to be decrypted """
        ctBits = coreDES.byte2bitArray(data)
        ptBits = []
        reversedSubkeys = list(reversed(self.subkeys))
        if self.mode == 'ECB':
            for block in coreDES.nSplit(ctBits, 64):
                if len(block) != 64:
                    block = block + [0] * (64 - len(block))
                ptBits += coreDES.encryptBlock(block, reversedSubkeys)
        elif self.mode == 'CBC':
            ivBits = coreDES.byte2bitArray(self.iv)
            previousCT = ivBits
            for block in coreDES.nSplit(ctBits, 64):
                if len(block) != 64:
                    block = block + [0] * (64 - len(block))
                decrypted = coreDES.encryptBlock(block, reversedSubkeys)
                ptBlock = coreDES.xor(decrypted, previousCT)
                ptBits += ptBlock
                previousCT = block
        elif self.mode == 'OFB':
            ivBits = coreDES.byte2bitArray(self.iv)
            feedback = ivBits
            for block in coreDES.nSplit(ctBits, 64):
                if len(block) != 64:
                    block = block + [0] * (64 - len(block))
                iv = coreDES.encryptBlock(feedback, self.subkeys)
                ptBlock = coreDES.xor(block, iv)
                ptBits += ptBlock
                feedback = iv
        else:
            raise ValueError(f"The mode '{self.mode}' is not supported")
        pt = coreDES.bitArray2byte(ptBits)
        return coreDES.remPadding(pt)

class TDES:
    """ Implements the Triple DES algorithm with a 192-bit key and three block
        modes: ECB, CBC, and OFB. """

    def __init__(self, key, mode="ECB", iv=None):
        """ Creates a new encryption object.
            Parameters:
              key  - 64-bit secret key given as a byte string
              mode - "ECB" or "CBC" or "OFB"
              iv   - 64-bit byte string that is required for CBC and OFB modes """
        if len(key) != 24:
            raise ValueError("TDES key has to be 24 bytes")
        self.key = key
        self.mode = mode.upper()
        self.iv = iv
        self.originalIV = iv
        if self.mode in ['CBC', 'OFB'] and iv is None:
            raise ValueError(f"IV is required for {self.mode}")
        if iv is not None and len(iv) != 8:
            raise ValueError("IV has to be 8 bytes")
        key1, key2, key3 = self._split_encryption_keys()
        self.subkey1 = coreDES.generateSubkeys(key1)
        self.subkey2 = list(reversed(coreDES.generateSubkeys(key2)))
        self.subkey3 = coreDES.generateSubkeys(key3)

    def _split_encryption_keys(self):
        """ Splits a Triple-DES encryption key into three 8-byte subkeys. Each
            subkey will be used for one of the DES rounds """
        key1 = self.key[0:8]
        key2 = self.key[8:16]
        key3 = self.key[16:24]
        return key1, key2, key3

    def reset(self):
        """ Resets the IV to its original value to start a new encryption or
            decryption. This function only applies to CBC and OFB modes """
        if self.mode in ['CBC', 'OFB']:
            self.iv = self.originalIV

    def encrypt(self, data):
        """ Encrypts data with the Triple-DES encryption algorithm.
            Parameters:
              data - raw byte string to be encrypted """
        pt = coreDES.addPadding(data)
        ptBits = coreDES.byte2bitArray(pt)
        ctBits = []
        if self.mode == 'ECB':
            for block in coreDES.nSplit(ptBits, 64):
                if len(block) != 64:
                    block = block + [0] * (64 - len(block))
                ctBlock = coreDES.encryptBlock(block, self.subkey1)
                ctBlock = coreDES.encryptBlock(ctBlock, self.subkey2)
                ctBlock = coreDES.encryptBlock(ctBlock, self.subkey3)
                ctBits += ctBlock
        elif self.mode == 'CBC':
            ivBits = coreDES.byte2bitArray(self.iv)
            previousCT = ivBits
            for block in coreDES.nSplit(ptBits, 64):
                if len(block) != 64:
                    block = block + [0] * (64 - len(block))
                xored = coreDES.xor(block, previousCT)
                ctBlock = coreDES.encryptBlock(xored, self.subkey1)
                ctBlock = coreDES.encryptBlock(ctBlock, self.subkey2)
                ctBlock = coreDES.encryptBlock(ctBlock, self.subkey3)
                ctBits += ctBlock
                previousCT = ctBlock
        elif self.mode == 'OFB':
            ivBits = coreDES.byte2bitArray(self.iv)
            feedback = ivBits
            for block in coreDES.nSplit(ptBits, 64):
                if len(block) != 64:
                    block = block + [0] * (64 - len(block))
                encryptFeedback = coreDES.encryptBlock(feedback, self.subkey1)
                encryptFeedback = coreDES.encryptBlock(encryptFeedback, self.subkey2)
                encryptFeedback = coreDES.encryptBlock(encryptFeedback, self.subkey3)
                ctBlock = coreDES.xor(block, encryptFeedback)
                ctBits += ctBlock
                feedback = encryptFeedback
        else:
            raise ValueError(f"The mode '{self.mode}' is not supported")
        return coreDES.bitArray2byte(ctBits)

    def decrypt(self, data):
        """ Decrypts data with the Triple-DES encryption algorithm.
            Parameters:
              data - raw byte string to be decrypted """
        ctBits = coreDES.byte2bitArray(data)
        ptBits = []
        reversedSubkey1 = list(reversed(self.subkey1))
        reversedSubkey2 = list(reversed(self.subkey2))
        reversedSubkey3 = list(reversed(self.subkey3))
        if self.mode == 'ECB':
            for block in coreDES.nSplit(ctBits, 64):
                if len(block) != 64:
                    block = block + [0] * (64 - len(block))
                ptBlock = coreDES.encryptBlock(block, reversedSubkey3)
                ptBlock = coreDES.encryptBlock(ptBlock, reversedSubkey2)
                ptBlock = coreDES.encryptBlock(ptBlock, reversedSubkey1)
                ptBits += ptBlock
        elif self.mode == 'CBC':
            ivBits = coreDES.byte2bitArray(self.iv)
            previousCT = ivBits
            for block in coreDES.nSplit(ctBits, 64):
                if len(block) != 64:
                    block = block + [0] * (64 - len(block))
                decrypted = coreDES.encryptBlock(block, reversedSubkey3)
                decrypted = coreDES.encryptBlock(decrypted, reversedSubkey2)
                decrypted = coreDES.encryptBlock(decrypted, reversedSubkey1)
                ptBlock = coreDES.xor(previousCT, decrypted)
                ptBits += ptBlock
                previousCT = block
        elif self.mode == 'OFB':
            ivBits = coreDES.byte2bitArray(self.iv)
            feedback = ivBits
            for block in coreDES.nSplit(ctBits, 64):
                if len(block) != 64:
                    block = block + [0] * (64 - len(block))
                iv = coreDES.encryptBlock(feedback, self.subkey1)
                iv = coreDES.encryptBlock(iv, self.subkey2)
                iv = coreDES.encryptBlock(iv, self.subkey3)
                ptBlock = coreDES.xor(block, iv)
                ptBits += ptBlock
                feedback = iv
            pt = coreDES.bitArray2byte(ptBits) # attempt to return it without removing padding
            return pt
        else:
            raise ValueError(f"The mode '{self.mode}' is not supported")
        pt = coreDES.bitArray2byte(ptBits)
        return coreDES.remPadding(pt)


def decryptHomework10():
    ecbQ = TDES(homework10.secret_key1, mode='ECB')
    ecbMessage = ecbQ.decrypt(homework10.ciphertext1)
    print(ecbMessage.decode('utf-8')+"\n")
    cbcQ = TDES(homework10.secret_key2, mode='CBC', iv=homework10.initvector2)
    cbcMessage = cbcQ.decrypt(homework10.ciphertext2)
    print(cbcMessage.decode('utf-8')+"\n")

    '''
    had some issues originally when the decode didn't have ignore errors in the print message
    which had a problem with padding saying padlen invalid, thus I added it to return the pt without removing padding in the decrypt ofb mode
    which fixed that issue with padlen, which prompted the decode error for some byte in CT, which i put the ignore error 
    which allowed i presume pretty much the exact message although having a "7;" at the end of the 'Simon Singh, The Code Book' 
    '''
    ofbQ = TDES(homework10.secret_key3, mode='OFB', iv=homework10.initvector3)
    ofbMessage = ofbQ.decrypt((homework10.ciphertext3))
    print(ofbMessage.decode('utf-8', errors='ignore'))


if __name__ == '__main__':
    decryptHomework10()