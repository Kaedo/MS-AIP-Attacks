# Goal
- Provide scripts that exctract all secrets from a users AD RMS account
  - This includes the Security Processer Certificate machine keys (public and private)
  - The public and private keys from Rights Account Certificate and Client Licensor Certificate
  - Exctraction of Use License content keys

### Note
- Bash scripts
	- requires adaption to non NixOS linux systems
	- Input files have a specific name scheme ({clc,rac,eul}.drm)
	- they are directly copied from windows clients and need to be in _input_ dir
	- processed files are found in the dir _processed_ and _output_
- Input files
	- Microsofts format of the files (GIC, CLC, SPC, etc) does contain zero bytes ('00' in hex)
	- They are normalized and reformated via **prepare.sh**
- DPAPI
	- I am not quite sure, under which circumstances Microsoft requires the optional entropy for the CryptProtect and CryptUnprotect function
	- You easily can observe the optional entropy value with the help of the APIMonitor and the unprotect.exe provided by me
- MSIPP-SK
	- Microsoft protects the __MSIPP-SK__ value not only via DPAPI, but also via an obfuscation, what they call RSAVault
	- This RSAVault is a RSA PKCS#1 v1.5 enc-/decryption of the 48 bytes which are used as input into the SHA-256 key derivation function used to encrypt/decrypt the unprotected MSIPP-MK RSA private key (SPC private key)

# Limitations
- DPAPI unprotect must be done on the Windows Account used for RMS
- MSIPP-SK deobfuscation can be done on any Windows 7 and above OS
