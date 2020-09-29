import binascii

f = open('msipp-sk-deobfuscate/msipp-sk-unprotected-plain.dat','rb')
sk_bytes = f.read()
print(binascii.hexlify(sk_bytes).decode('utf-8')[:96])
