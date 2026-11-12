# axelwas-datrigel-cryptography

## usage 

to start server do

```
cargo run -- -S
```

to upload a file do

```
cargo run -- -a <address> -p <password> -f <file to upload>
```

example:

```
cargo run -- -a 127.0.0.1:6767 -p pass -f README.md
```

to calculate merkel hash do:

```
cargo run -- -m <address> -p <password> -f <file to write hash too>
```

to download a file do:

```
cargo run -- -d <address> -p <password> -f <filename>
```

example:

```
cargo run -- -d 127.0.0.1:6767 -p pass -f README.md
```

NOTE: the file argument is both the name of the file on the server and the destination the client will download and write the file too. In the example README.md cannot exist in the workind diretcory for the download to suceed.

## Protocol

The server needs to save the signature, the nonce, the name, and the data.

All letters in protocoll must be ascii.

To get file do this:
```
GET <resource-name>

```
Note that you have to end with all messages with two new line characters "\n"


server responds:
```
signature: <sign>
length: <length-in-bytes>
nonce: <nonce>

[data]

```

Client can also demand a list of all files. This is so you can generate a merkle tree.
```
LIST

```

The server responds:
```
<filename1>
<filename2>
<filename3>

```

to upload data do this:
```
PUT <resource-name>
signature: <sign>
length: <length-in-bytes>
nonce: <nonce>

[data]

```

Server responds

```
OK
``` EX bytes