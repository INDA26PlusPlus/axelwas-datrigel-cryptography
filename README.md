# axelwas-datrigel-cryptography

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
```