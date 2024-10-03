1. Generate Public and Private Key Using ssh-keygen
    Command:	ssh-keygen -t rsa -b 2048 -f mykey
    o/p: mykey: The private key.
    mykey.pub: The public key.

2. Convert the Public Key to PEM Format
    Command: ssh-keygen -f mykey.pub -e -m PEM > mykey_public.pem 

3. Convert the Private Key to PEM Format
    Command: ssh-keygen -p -m PEM -f mykey

4. Command to Run under scripts
    ./gen-firmware-tar.py -j -s -o "man.a.tar" -m "zzz-yyy" -c "xyz.xxxx.Software.Element.wcs.Type.BIOS" -v "yyy.OBMC.24.05.10" -e "None" xxx.0.BS.1B09.GN.1.7z yyy.0.BS.1B09.GN.1.7z zzz.0.BS.1B09.GN.1.7z 

5. Command for help
    ./gen-firmware-tar.py --help

6. Output file (under output) (tar -xvf man.a.tar)
    man.a.tar -> consist MANIFEST.json & MANIFEST.json.sig

7. Public and Private key path
    Under key dir
    