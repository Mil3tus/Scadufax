# scadufax installation script
# full source code on GitHub: https://github.com/Mil3tus/Scadufax
# created by Mil3tus

# create temporary folder
echo "[+] creating temporary folder"
sleep 0.5
mkdir temp
echo "[+] folder created"
sleep 0.5
echo "[+] decompressing files"
# uncompress
tar -C temp -xf scadufax.beta_noudp.tar.gz
sleep 0.5
echo "[+] copying binary to /usr/bin/"
cp temp/scadufax /usr/bin/scadufax
mkdir /usr/share/scadufax
echo "[+] copying database to /usr/share/scadufax/"
cp -r temp/database /usr/share/scadufax
rm -r temp
echo "[+] installation complete"
sleep 0.5
