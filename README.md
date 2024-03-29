# Goal
- Provide scripts that exctract all secrets from a users AD/Azure RMS or AIP account
  - This includes the Security Processer Certificate machine keys (public and private)
  - The public and private keys from Rights Account Certificate and Client Licensor Certificate
  - Exctraction of Use License content keys
  - Decrypt and encrypt documents under this content key.

### Youtube
- You can find my video series "Azure Information Protection under the hood" on Youtube explaining the background of this scripts in much more detail.
  - [01 - Create and Open a protected Word document](https://www.youtube.com/watch?v=aikT8zQAXqc)
  - [02 - Generating and protecting the SPC and private key](https://www.youtube.com/watch?v=hHQ2yeo24uI)
  - [03 - Unprotect an AIP Word file](https://www.youtube.com/watch?v=YAd3Bsi7SV0)
  - [04 - Modify and Reprotect an AIP Word file](https://www.youtube.com/watch?v=6vCPAFJB_gU)

### Note
- Requierement
	- parse.py access a .NET dll via [pythonnet](https://pythonnet.github.io/)
	- you need access to a .NET Cli. For mac and linux you can install it this [opensource implementation.](https://www.mono-project.com/docs/about-mono/supported-platforms/macos/)
	- Installation guide of the [pythonnet lib:](https://github.com/pythonnet/pythonnet/wiki/Troubleshooting-on-Windows,-Linux,-and-OSX)
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
- Parsing and decryption of Publishing Licenses is currently not working

# Dissertation
- If you want more structured information about AD/Azure RMS and AIP you can find my dissertation [online](https://mgrothe.de/posts/dissertation-phd-research-security-microsoft-rms-ad-azure-information-protection-cisco-huawei-ipsec-bleichenbacher/)
