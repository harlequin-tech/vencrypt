# vencrypt

- Build
        make

- load
        sudo insmod vencrypt.ko encrypt=1 key=0123456789ABCDEF0123456789ABCDEF

# notes
- works only with 128 bit keys as key size is static in AES lib
- Built and tested on Linux iserve 5.15.0-87-generic #97-Ubuntu SMP Tue Oct 3 09:52:42 UTC 2023 aarch64 aarch64 aarch64 GNU/Linux

# testing
make
sudo insmod vencrypt.ko encrypt=1 key=0123456789ABCDEF0123456789ABCDEF
sudo -i
dd if=/dev/urandom of=rand.256 bs=128K count=2
2+0 records in
2+0 records out
262144 bytes (262 kB, 256 KiB) copied, 0.00289021 s, 90.7 MB/s
cat rand.256 > /dev/vencrypt_pt
cat /dev/vencrypt_ct > rand.256.enc
ls -lh rand.256*
-rw-r--r-- 1 root root 256K Oct 21 07:04 rand.256
-rw-r--r-- 1 root root 257K Oct 21 07:05 rand.256.enc

sha rand.256*
sha1sum       sha224sum     sha256sum     sha384sum     sha512sum     shadowconfig  shasum
sha256sum rand.256*
2dda095374ce07985f4aa890f12cabe321ae9c158d83e68f8b13dcae76a0bfe2  rand.256
52d03446df4f3ee7e7d374d795792d8e2814d2d8ec8001ff46423b4f45762aeb  rand.256.enc

logout
sudo rmmod vencrypt
sudo insmod vencrypt.ko encrypt=0 key=0123456789ABCDEF0123456789ABCDEF
sudo -i
cat rand.256.enc > /dev/vencrypt_ct
cat /dev/vencrypt_pt > rand.256.dec
ls -lh rand.256*
-rw-r--r-- 1 root root 256K Oct 21 07:04 rand.256
-rw-r--r-- 1 root root 256K Oct 21 07:06 rand.256.dec
-rw-r--r-- 1 root root 257K Oct 21 07:05 rand.256.enc

sha256sum rand.256*
2dda095374ce07985f4aa890f12cabe321ae9c158d83e68f8b13dcae76a0bfe2  rand.256
2dda095374ce07985f4aa890f12cabe321ae9c158d83e68f8b13dcae76a0bfe2  rand.256.dec
52d03446df4f3ee7e7d374d795792d8e2814d2d8ec8001ff46423b4f45762aeb  rand.256.enc

