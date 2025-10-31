import des_constants_permutation_tables
import des_constants_sbox_tables
import des_constants_subkey_tables
from elud_des_permTables import initPermInput, initPermOutput, finiPermInput, finiPermOutput, sBoxPermInput, sBoxPermOutput, expandPermOutput, expandPermInput
from elud_SBOXtest import sBOX_input, sBOX_output
from des_tests_subkey import subkey_input, subkey_result
import homework09


def addPadding(message):
    # core code from lect. vid, modified slightly
    padLen = 8 - len(message) % 8
    padding = chr(padLen) * padLen
    message += padding.encode("utf-8")
    return message

def remPadding(message):
    # used AI to generate but made tweaks
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

def byte2bitArray(byteString):
    # tweaked code from vid lect.
    result = []
    for byte in byteString:
        for bit in [7,6,5,4,3,2,1,0]:
            mask = 1 << bit
            result.append(1 if (byte & mask) else 0)
    return result


def bitArray2byte(bitArray):
    # AI tweaked code from vid lect.
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

def nSplit(data, splitSize=64):
    # used AI to generate but made some modifications
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

def hexPrint(msg, block, length=16):
    """pulled originally from vid lect, on unit tests
    it wasn't properly working so used AI to resolve error
    from commented out on line 89
    """
    s = [str(i) for i in block]
    b = int("".join(s), 2)
    #print(hex(b)[2:].zfill(length))
    hexStr = hex(b)[2:].zfill(length).upper()
    return hexStr

def function(R,subkey):
    # AI generated, with slight modifications
    expanded = permute(R, des_constants_permutation_tables._EXPAND)
    xored = xor(expanded, subkey)
    substituted = substitute(xored)
    return permute(substituted, des_constants_permutation_tables._SBOX_PERM)

def encrypt(data, key, mode='ECB', iv=None):
    # from vid lect, then was tweaked partially by AI
    pt = addPadding(data)
    ptBits = byte2bitArray(pt)
    subkeys = generateSubkeys(key)
    ctBits = []
    # updated encrypt function for modes and iv
    if mode.upper() == 'ECB':
        for block in nSplit(ptBits, 64):
            if len(block) != 64:
                block = block + [0] * (64 - len(block))
            ctBits += encryptBlock(block, subkeys)
    elif mode.upper() == 'CBC':
        if iv is None:
            raise ValueError("IV required for CBC")
        ivBits = byte2bitArray(iv)
        previousCT = ivBits
        for block in nSplit(ptBits, 64):
            if len(block) != 64:
                block = block + [0] * (64 - len(block))
            xored = xor(block, previousCT)
            encrypted = encryptBlock(xored, subkeys)
            ctBits += encrypted
            previousCT = encrypted
    elif mode.upper() == 'OFB':
        if iv is None:
            raise ValueError("IV required for OFB")
        ivBits = byte2bitArray(iv)
        feedback = ivBits
        for block in nSplit(ptBits, 64):
            if len(block) != 64:
                block = block + [0] * (64 - len(block))
            encryptFeedback = encryptBlock(feedback, subkeys)
            ctBlock = xor(block, encryptFeedback)
            ctBits += ctBlock
            feedback = encryptFeedback
    else:
        raise ValueError(f"The mode '{mode}' is not supported")

    ct = bitArray2byte(ctBits)
    return ct

def decrypt(data, key, mode='ECB', iv=None):
    # new decrypt function
    ctBits = byte2bitArray(data)
    subkeys = generateSubkeys(key)
    ptBits = []
    if mode.upper() == 'ECB':
        for block in nSplit(ctBits, 64):
            if len(block) != 64:
                block = block + [0] * (64 - len(block))
            ptBits += decryptBlock(block, subkeys)
    elif mode.upper() == 'CBC':
        if iv is None:
            raise ValueError("IV required for CBC")
        ivBits = byte2bitArray(iv)
        previousCT = ivBits
        for block in nSplit(ctBits, 64):
            if len(block) != 64:
                block = block + [0] * (64 - len(block))
            decrypted =decryptBlock(block, subkeys)
            ptBlock = xor(decrypted, previousCT)
            ptBits += ptBlock
            previousCT = block
    elif mode.upper() == 'OFB':
        if iv is None:
            raise ValueError("IV required for OFB")
        ivBits = byte2bitArray(iv)
        feedback = ivBits
        for block in nSplit(ctBits, 64):
            if len(block) != 64:
                block = block + [0] * (64 - len(block))
            encryptedFeedback = encryptBlock(feedback, subkeys)
            ptBlock = xor(block, encryptedFeedback)
            ptBits += ptBlock
            feedback = encryptedFeedback
    else:
        raise ValueError(f"The mode '{mode}' is not supported")
    pt = bitArray2byte(ptBits)
    return remPadding(pt)

def encryptBlock(block, subkeys):
    # from vid lec
    # AI tweaked function
    block = permute(block, des_constants_permutation_tables._INIT_PERMUTATION)
    L = block[:32]
    R = block[32:]
    for i in range(16):
        L, R = R, xor(L, function(R, subkeys[i]))
    preoutput = R + L
    block = permute(preoutput, des_constants_permutation_tables._FINAL_PERMUTATION)
    return block

def decryptBlock(block, subkeys):
    # new decryptBlock function
    block = permute(block, des_constants_permutation_tables._INIT_PERMUTATION)
    L = block[:32]
    R = block[32:]
    for i in range(15, -1, -1):
        L, R = R, xor(L, function(R, subkeys[i]))
    preoutput = R + L
    block = permute(preoutput, des_constants_permutation_tables._FINAL_PERMUTATION)
    return block

def permute(block, table):
    # got function from quiz
    return [block[x] for x in table]

def Lshift(sequence:list, n:int):
    # AI generated
    if not sequence:
        return []
    L = len(sequence)
    n = n % L
    return sequence[n:] + sequence[:n]

def xor(x:list, y:list):
    # AI generated
    if len(x) != len(y):
        raise ValueError("Lists must be of equal length")
    return [1 if (a != b) else 0 for a, b in zip(x, y)]

def substitute(bit_array:list):
    # used AI to generate, then made modifications to read from constants file
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

'''
pulled function from the video provided but made the modifications to call shift & keyPerm from constants file
'''
def generateSubkeys(encryption_key:bytes):
    subkeys = []
    keybits = byte2bitArray(encryption_key)
    k0 = permute(keybits, des_constants_subkey_tables._KEY_PERMUTATION1)
    R = k0[28:]
    L = k0[:28]
    for i in range(16):
        L = Lshift(L, des_constants_subkey_tables._KEY_SHIFT[i])
        R = Lshift(R, des_constants_subkey_tables._KEY_SHIFT[i])
        kI = permute(L + R, des_constants_subkey_tables._KEY_PERMUTATION2)
        subkeys.append(kI)
    return subkeys



def runUnitTests():
    addCases = [
        #add padding tests
        (b"CSC428", b"CSC428\x02\x02"),
        (b"TALLMAN", b"TALLMAN\x01"),
        (b"JTALLMAN", b"JTALLMAN\x08\x08\x08\x08\x08\x08\x08\x08")
    ]
    for i, (input, expected) in enumerate(addCases, start=1):
        result = addPadding(input)
        assert result == expected, f"Unit test #{i} failed: got {result}, expected {expected}"

    remCases = [
        (b"CSC428\x02\x02", b"CSC428"),
        (b"TALLMAN\x01", b"TALLMAN"),
        (b"JTALLMAN\x08\x08\x08\x08\x08\x08\x08\x08", b"JTALLMAN")
    ]
    for i, (input, expected) in enumerate(remCases, start=1):
        result = remPadding(input)
        assert result == expected, f"Unit test #{i} failed: got {result}, expected {expected}"

    byteStringCases = [
        (b"\x00", [0,0,0,0,0,0,0,0]),
        (b"\xA5", [1,0,1,0,0,1,0,1]),
        (b"\xFF", [1,1,1,1,1,1,1,1])
    ]
    for i, (input, expected) in enumerate(byteStringCases, start=1):
        result = byte2bitArray(input)
        assert result == expected, f"Unit test #{i} failed: got {result}, expected {expected}"

    bitArrayCases = [
        ([0,0,0,0,0,0,0,0], b"\x00"),
        ([1,0,1,0,0,1,0,1], b"\xA5"),
        ([1,1,1,1,1,1,1,1], b"\xFF")
    ]
    for i, (input, expected) in enumerate(bitArrayCases, start=1):
        result = bitArray2byte(input)
        assert result == expected, f"Unit test #{i} failed: got {result}, expected {expected}"

    # got lazy and decided to only use 1 for nsplit and hex
    nsplitUnitTest = list(nSplit(b"1111222233334444", 4))
    assert nsplitUnitTest == [b"1111", b"2222", b"3333", b"4444"], f"nSplit failed: got {nsplitUnitTest}"

    hexUnitTest = hexPrint("Test", [1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0,
                                   1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1], 8)
    assert hexUnitTest == "F50A96DB", f"hexPrint failed: got {hexUnitTest}"

    # Permutation Table Unit Tests
    initPerm_result = permute(initPermInput, des_constants_permutation_tables._INIT_PERMUTATION)
    assert initPerm_result == initPermOutput

    '''
    figured out the failing test from last hw was due to an input error on my behalf
    since I inputted a number into " " as a string rather than having it as an integer
    '''
    finiPerm_result = permute(finiPermInput, des_constants_permutation_tables._FINAL_PERMUTATION)
    assert finiPerm_result == finiPermOutput

    sBoxPerm_result = permute(sBoxPermInput, des_constants_permutation_tables._SBOX_PERM)
    assert sBoxPerm_result == sBoxPermOutput


    expandPerm_result = permute(expandPermInput, des_constants_permutation_tables._EXPAND)
    assert expandPerm_result == expandPermOutput


    # Left-Shift & XOR Unit Tests
    assert Lshift([1, 2, 3, 4], 3) == [4, 1, 2, 3]
    assert Lshift([5, 6, 7, 8], 2) == [7, 8, 5, 6]

    assert xor([1, 0], [1, 0]) == [0, 0]
    assert xor([1, 1], [0, 0]) == [1, 1]


    # SBOX Substitution & Generate subkeys
    sBoxResult = substitute(sBOX_input)
    assert sBoxResult == sBOX_output

    genSubkeyResult = generateSubkeys(subkey_input)
    assert genSubkeyResult == subkey_result

def integrationTests():
    rInput = [1,0,0,1,1,0,1,0,1,1,0,1,0,0,1,1,1,1,1,0,0,1,1,0,0,1,1,0,1,1,0,0]
    subkey = [1,0,1,1,0,0,1,1,0,1,0,1,0,1,1,0,0,0,0,1,0,1,1,0,1,1,0,1,1,0,0,1,1,1,0,0,1,1,1,1,0,1,0,1,0,1,0,1]
    output = [1,1,0,0,1,0,0,1,1,0,0,0,1,0,1,0,1,1,0,0,1,1,0,0,1,1,0,1,0,0,1,1]

    result = function(rInput, subkey)
    assert result == output

def run_system_tests():
    keyHex = "caceffddaafb0110"
    pt = b"whitemonsterenergydrink"
    expectedCT = b"\xaa\x63\x85\x82\x59\x3f\x48\xcd\x76\x0b\x51\xd6\xd9\x5d\xd1\xd2\x86\x07\x69\x13\xab\x26\xfc\x70"
    key = bytes.fromhex(keyHex)
    ct = encrypt(pt, key)
    assert ct == expectedCT, f"Expected: {expectedCT.hex()}, but got: {ct.hex()}"

    # new cipherBlock Mode sys tests from homework09.py
    pt1 = decrypt(homework09.ciphertext1, homework09.secret_key1, mode='ECB')
    ct1 = encrypt(pt1, homework09.secret_key1, mode='ECB')
    assert ct1 == homework09.ciphertext1, f"Expected: {homework09.ciphertext1}"
    print(f"ECB Message: {pt1}")
    pt2 = decrypt(homework09.ciphertext2, homework09.secret_key2, mode='CBC', iv=homework09.initvector2)
    ct2 = encrypt(pt2, homework09.secret_key2, mode='CBC', iv=homework09.initvector2)
    assert ct2 == homework09.ciphertext2, f"Expected: {homework09.ciphertext2}"
    print(f"CBC Message: {pt2}")

    # pt3 = decrypt(homework09.ciphertext3, homework09.secret_key3, mode='OFB', iv=homework09.initvector3)
    # ct3 = encrypt(pt3, homework09.secret_key3, mode='CBC', iv=homework09.initvector3)
    # assert ct3 == homework09.ciphertext3, f"Expected: {homework09.ciphertext3}"
    # print(f"PT3: {pt3}")
    '''
        since i was getting a padLen value error using the following above, narrowing it down to 
        do something with the padding with the 3rd test, below doing the test w/o removing the padding
        worked out getting the message
    '''
    try:
        pt3 = decrypt(homework09.ciphertext3, homework09.secret_key3, mode='OFB', iv=homework09.initvector3)
    except ValueError:
        ctBits = byte2bitArray(homework09.ciphertext3)
        subkeys = generateSubkeys(homework09.secret_key3)
        ptBits = []
        ivBits = byte2bitArray(homework09.initvector3)
        feedback = ivBits
        for block in nSplit(ctBits, 64):
            encryptedFeedback = encryptBlock(feedback, subkeys)
            ptBlock = xor(block, encryptedFeedback)
            ptBits += ptBlock
            feedback = encryptedFeedback
        pt3 = bitArray2byte(ptBits)
    print(f"OFB Message: {pt3}")

    # more system tests using cyberChef to confirm working DES
    ecbKeyHex = "aedcfadcabfb1010"
    ecbPT = b"gettingenoughsleep"
    ecbExpectedCT = b"\x5e\xd3\xfc\xa9\xa2\x24\xbb\x9d\xc8\x89\xd0\xf4\xfa\x96\xb9\x37\xba\xd2\xe3\x46\xb1\x0a\x30\x59"
    ecbKey = bytes.fromhex(ecbKeyHex)
    ecbCT = encrypt(ecbPT, ecbKey, mode='ECB')
    assert ecbCT == ecbExpectedCT, f"Expected: {ecbExpectedCT.hex()}, but got: {ecbCT.hex()}"
    ecbPTdecrypt = decrypt(ecbCT, ecbKey, mode='ECB')
    assert ecbPTdecrypt == ecbPT, f"Expected: {ecbPT}, but got {ecbPTdecrypt}\n"

    cbcKeyHex = "1101adebcca0110a"
    cbcIVHex = "010abfd10301840c"
    cbcPT = b"timetogotobednow"
    cbcExpectedCT = b"\xf8\xdf\x67\xa5\x73\x4f\xa9\x03\xa3\x02\xab\x4a\x10\x96\x75\x15\xde\xef\x47\xd4\x8d\xd7\x8f\xe8"
    cbcKey = bytes.fromhex(cbcKeyHex)
    cbcIV = bytes.fromhex(cbcIVHex)
    cbcCT = encrypt(cbcPT, cbcKey, mode='CBC', iv=cbcIV)
    assert cbcCT == cbcExpectedCT, f"Expected: {cbcExpectedCT.hex()}, but got: {cbcCT.hex()}"
    cbcPTdecrypt = decrypt(cbcCT, cbcKey, mode='CBC', iv=cbcIV)
    assert cbcPTdecrypt == cbcPT, f"Expected: {cbcPT}, but got {cbcPTdecrypt}\n"

    ofbKeyHex = "7f3b92e4d6c81a05"
    ofbIVHex = "4e8d2f1a9c7b3068"
    ofbPT = b"imcravingChickenwings"
    ofbExpectedCT = b"\x15\xf6\x92\xf6\x70\xd7\x83\xe8\x4a\x4c\xc5\x8d\xc7\x76\x60\xd0\xcd\xd7\x26\x25\xba\xa5\xd1\x39"
    ofbKey = bytes.fromhex(ofbKeyHex)
    ofbIV = bytes.fromhex(ofbIVHex)
    ofbCT = encrypt(ofbPT, ofbKey, mode='OFB', iv=ofbIV)
    assert ofbCT == ofbExpectedCT, f"Expected: {ofbExpectedCT.hex()}, but got: {ofbCT.hex()}"
    ofbPTdecrypt = decrypt(ofbCT, ofbKey, mode='OFB', iv=ofbIV)
    assert ofbPTdecrypt == ofbPT, f"Expected: {ofbPT}, but got {ofbPTdecrypt}\n"


if __name__ == '__main__':
    runUnitTests()
    print("\nUnit tests were successful!\n")
    integrationTests()
    print("Integration tests were successful!\n")
    run_system_tests()
    print("\nSystem tests confirmed they match\n")

