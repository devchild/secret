# secret
Command line tool to encrypt and decrypt key value strings.


Depends on OPENSSL
Get started:
git clone https://github.com/devchild/secret.git
cd secret
mkdir bin
cd bin
cmake ..
make

Usage:

Create a file containing key value strings.
eg. 
key1=value1
key2=value2
key3=value3

Encrypt the file using following command.
./secret -pwd yourpassword -enc -f yourkeyvaluefile.txt

To decrypt use following command:
./secret -pwd yourpassword -dec -f your_encrypted_keyvaluefile.txt


You can also pipe key_value strings into the tool eg.

> echo key=value | ./secret -pwd pwd -enc
> key=x/bdAsomgLWKOx9MMn/LfA==
