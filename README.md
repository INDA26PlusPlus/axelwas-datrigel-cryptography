# axelwas-datrigel-cryptography

## Protocol

To get file do this:
```
GET <resource-name>

```
Note that you have to end with all messages with two new line characters "\n"


server responds:
```
signature: <sign>
hash: <hash>
length: <length-in-bytes>

[data]

```

to upload data do this:
```
PUT <resource-name>
signature: <sign>
length: <length-in-bytes>

[data]

```

Server responds

```
OK
```