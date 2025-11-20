"""
GNU Privacy Guard Project - CSC428

Group Members:
Elijah Ludwig
Dhruv Kagatimath
"""

import sys, os.path, hashlib, getpass, gpg_consts
from TDES import TDES


def s2k_m0_md5(passphrase, keyLength=24):
    """
    Derives a key from a passphrase using the GPG s2k move 0 with MD5
    It repeatedly hashes 0x00 bytes + passphrase until KeyLength amount of bytes
    of the key material are produced
    """
    if isinstance(passphrase, str):
        passphrase = passphrase.encode('utf-8')

    keyMaterial = b''
    preload = b''

    while len(keyMaterial) < keyLength:
        md5Hash = hashlib.md5()
        md5Hash.update(preload + passphrase)
        keyMaterial += md5Hash.digest()
        preload += b'\x00'

    return keyMaterial[:keyLength]


def processPackets(rawData):
    """
    Reads a single GPG packet from bytes and return the header and body
    This supports both old and new style packet formats
    """
    packetStartMask = 0x80
    packetVersionMask = 0x40
    packetNewTagMask = 0x3f
    packetOldTagMask = 0x3c
    packetOldLenMask = 0x03

    headerByte = rawData[0]
    if (headerByte & packetStartMask) == 0:
        raise ValueError("Invalid GPG packet")

    if (headerByte & packetVersionMask) == 0:
        # Old-style packet format
        version = "old-ctb"
        tagType = (headerByte & packetOldTagMask) >> 2
        gpgPacketLenType = (headerByte & packetOldLenMask)

        if gpgPacketLenType == 0:
            dataLength = rawData[1]
            dataOffset = 2
        elif gpgPacketLenType == 1:
            dataLength = int.from_bytes(rawData[1:3], "big")
            dataOffset = 3
        elif gpgPacketLenType == 2:
            dataLength = int.from_bytes(rawData[1:5], "big")
            dataOffset = 5
        elif gpgPacketLenType == 3:
            raise ValueError("Packet length not determinable")
    else:
        # New-style packet format
        version = "new-ctb"
        tagType = (headerByte & packetNewTagMask)

        octet1 = int(rawData[1])
        if octet1 < 192:
            dataLength = octet1
            dataOffset = 2
        elif octet1 < 224:
            octet2 = int(rawData[2])
            dataLength = ((octet1 - 192) << 8) + octet2 + 192
            dataOffset = 3
        elif octet1 == 255:
            dataLength = int.from_bytes(rawData[2:6], "big")
            dataOffset = 6
        else:
            raise ValueError(f"GPG packet has invalid size (octet1 = {octet1})")

    start = dataOffset
    finish = dataOffset + dataLength
    gpgPkt = {
        'ver': version,
        'ctb': hex(rawData[0])[2:],
        'tag': tagType,
        'hlen': dataOffset,
        'poff': dataOffset,
        'plen': dataLength,
        'pbuf': rawData[start:finish],
    }
    return gpgPkt


def parse_symkey_enc_session_packet(packetData):
    """
    Parses a Symmetric-Key Encrypted Session Key Packet.

    This returns the version, cipher alg, s2k mode, and hash algorithm
    """
    version = packetData[0]
    cipherAlgo = packetData[1]
    s2kMode = packetData[2]
    hashAlgo = packetData[3] if s2kMode == 0 else None

    return {
        'version': version,
        'cipherAlgo': cipherAlgo,
        's2kMode': s2kMode,
        'hashAlgo': hashAlgo
    }


def parse_sym_enc_int_data_packet(packetData):
    """
    Parses a Symmetrically Encrypted Integrity Protected Data Packet.
    
    Returns the version byte and remaining encrypted data bytes
    """
    version = packetData[0]
    encryptedData = packetData[1:]

    return {
        'version': version,
        'encryptedData': encryptedData
    }


def decryptData(encryptedData, sessionKey):
    """
    Decrypts GPG encrypted data using the TDES class in GPG mode.
    """
    cipher = TDES(sessionKey, mode='GPG')
    return cipher.decrypt(encryptedData)


def parseLiteralDataPackets(packetData):
    """
    Parse through a Literal Data packet into filename, timestamp, and data

    Returns a dict with the file format, name, date, and the contents the file has
    """
    formatByte = chr(packetData[0])
    filenameLen = packetData[1]
    filename = packetData[2:2 + filenameLen].decode('utf-8', errors='ignore')
    date = int.from_bytes(packetData[2 + filenameLen:6 + filenameLen], 'big')
    data = packetData[6 + filenameLen:]

    return {
        'format': formatByte,
        'filename': filename,
        'date': date,
        'data': data
    }


def decryptGPGfile(filename, passphrase):
    """
    Decrypts a GPG file
    """
    with open(filename, 'rb') as f:
        fileContents = f.read()

    packets = []
    offset = 0
    eof = len(fileContents)

    while offset < eof:
        packet = processPackets(fileContents[offset:])
        packets.append(packet)
        offset += packet['poff'] + packet['plen']

    sessionPacket = None
    encryptedPacket = None

    for packet in packets:
        if packet['tag'] == gpg_consts._ptag_symkey_enc_session:
            sessionPacket = parse_symkey_enc_session_packet(packet['pbuf'])
        elif packet['tag'] == gpg_consts._ptag_sym_enc_int_data:
            encryptedPacket = parse_sym_enc_int_data_packet(packet['pbuf'])

    if sessionPacket is None:
        raise ValueError("No Symmetric-Key Encrypted Session Key Packet found")
    if encryptedPacket is None:
        raise ValueError("No Symmetrically Encrypted Integrity Protected Data Packet found")
    if sessionPacket['cipherAlgo'] != 2:
        raise ValueError(f"Unsupported cipher algorithm: {sessionPacket['cipherAlgo']}")
    if sessionPacket['s2kMode'] != 0:
        raise ValueError(f"Unsupported S2K mode: {sessionPacket['s2kMode']}")

    sessionKey = s2k_m0_md5(passphrase, keyLength=24)
    decryptedData = decryptData(encryptedPacket['encryptedData'], sessionKey)

    literalPacket = processPackets(decryptedData)
    if literalPacket['tag'] != gpg_consts._ptag_literal_data:
        raise ValueError(f"Expected literal data packet, got tag {literalPacket['tag']}")
    literalData = parseLiteralDataPackets(literalPacket['pbuf'])

    return literalData['filename'], literalData['data']


def main():
    """
    This takes the encrypted .gpg file as an argument, asks for the passphrase, decrypts the file,
    then writes the plaintext to the disk
    """

    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <encrypted_file.gpg>")
        print(f"Decrypts GPG files encrypted with:" +
              " --allow-old-cipher-algos -z 0 --symmetric --cipher-algo 3DES --s2k-digest-algo MD5 --s2k-mode 0 {sample.txt.gpg} {sample.txt}")
        sys.exit(1)
    filename = sys.argv[1]

    # Verify the file exists & if it exists will prompt user password used to encrypt file
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' does not exist")
        sys.exit(1)
    passphrase = getpass.getpass("Password: ")
    # decrypt file
    try:
        outputFilename, plaintextData = decryptGPGfile(filename, passphrase)
        with open(outputFilename, 'wb') as f:
            f.write(plaintextData)
        print(f"Successfully decrypted to: {outputFilename}")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()