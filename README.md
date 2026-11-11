# axelwas-datrigel-cryptography

## Protocol

The server needs to save the signature, the nonce, the name, and the data.

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