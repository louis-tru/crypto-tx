#!/bin/sh

# my account
# privateKey: 0xa4a3242eebcbfe4f8b183fa05a30b38a3d97bb8121fa9ab801f7a222ab2274b7
# publicKey:  0x02fb406d76aa8892ac685c29d01e7b98f3936c66a86078269ed1f464a79ffe0f68

# you account
# privateKey: 0x39dc3b3e72e27095838e20d35b88837724b58f526bfea4aa05f1c24f5d9e82cd
# publicKey:  0x026a2eb230e95af2ae69b7f0516548ced0a86d6725ac411f02be2cad1864dd42bd

echo -G

node ./shell.js -G

echo encrypt:

node ./shell.js -E -k 0xa4a3242eebcbfe4f8b183fa05a30b38a3d97bb8121fa9ab801f7a222ab2274b7 -p 0x026a2eb230e95af2ae69b7f0516548ced0a86d6725ac411f02be2cad1864dd42bd -d 楚学文 -iv 0xfe22bf05298575d79ed2ce24e28a05c8

echo decrypt:

node ./shell.js -D -k 0x39dc3b3e72e27095838e20d35b88837724b58f526bfea4aa05f1c24f5d9e82cd -p 0x02fb406d76aa8892ac685c29d01e7b98f3936c66a86078269ed1f464a79ffe0f68 -d 0x67f539d1db77eb568fc9672cf25f9ae4 -iv 0xfe22bf05298575d79ed2ce24e28a05c8
