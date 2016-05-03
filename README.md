## Message Cipher

An exploration of node's crypto Private/Public key algorithms.

Installing globally provides binary: ```msg-cipher```

## Install
```bash
nvm use 5 # works best if run with node 5x
npm install
```

### Generate a new private key file
```bash
node index.js generate
```

### Force-regenerate private key file
```bash
node index.js generate -f
```

### Generate private key and dump to output
```bash
node index.js generate -R
```

### Read info about current private key file
```bash
node index.js read
```

### Encrypt a message
```bash
node index.js encrypt [--priv <private-key>] [--pub <public-key>] <msg>
```

### Decrypt a message
```bash
node index.js decrypt [--priv <private-key>] [--pub <public-key>] <encrypted-msg>
```

### Encrypting message to other user
```bash
node index.js encrypt [--priv <sender-private-key>] --pub <receiver-public-key> <msg>
```

### Decrypting message sent by sender to other user
```bash
node index.js decrypt [--priv <sender-private-key>] --pub <receiver-public-key> <encrypted-msg>
```

### Decrypting message from other user
```bash
node index.js decrypt [--priv <receiver-private-key>] --pub <sender-public-key> <encrypted-msg>
```


## Example Script

```bash
export MY_PRI="03ed57857b42c69bf0559087d748d78a83f011d1459274c8f09f0ae3afe25d70f75f83684dbf46b959cf2a403580f5fbf347e18515cd47e9e27c07e87e1ddf74b908477337e5f7ef"
export MY_PUB="0406baf5bd0db574d342fba3e53619a931652e6f8088c7f415b6af7ee191c1bddb571c4fe2a4ccb61aec940079a4424ef5fc4d222ab3fca22e0d5721511eebfe607820536642a3c71d02f84661b744a890cb8778e145803560ab04b69ee71a8e61b90a4ce3fde92c15e5d54d76e048bbd712475f0a772505acb9458c9d7e8e14c5e6466f937837b11cacfbf55e0def2753"

export TEST_PRI="9f6ba49209d617402b5459f33c2b2f56edcdeb8f021242e2ec54916b9a5485cc6e4852c5061037d14f9ddbbfc8a34638f1730094faffb1a0508a7872eb32fd5d1c40d1b516890c"
export TEST_PUB="0404832e0a1ba719ed3ae03ba86e356fd1d3bc8df89d824cbd5bdd89439bcf45aae2c65e0f6af0d340638776545ad69fe7fbe948f1d3ad02ef6c94b52b274482e49d14b5d575c423be01df7252962db72c99e3b4c18c87e9f25f16bcbcfde371ca784d0ff2be1697ff96369ff8a9172f0045f30ae90f79c0bea47b51efe1a8ede05a698abb51c58a7494dba9bc3dfef79f"

node index.js encrypt --priv $MY_PRI --pub $TEST_PUB "This is a test"

# Outputs >>
# Encrypted Message:
# 1bc089d5d64e87f2c6d1aaf170fc8330a8630eeb85dcb262b30ee465e179749e8616e4192d8acf124335f34bb49e16ac6543f36905dd9ab478bb30f57f2bc6bfd8da326c6704c1335f4611d96e

node index.js decrypt --priv $MY_PRI --pub $TEST_PUB 1bc089d5d64e87f2c6d1aaf170fc8330a8630eeb85dcb262b30ee465e179749e8616e4192d8acf124335f34bb49e16ac6543f36905dd9ab478bb30f57f2bc6bfd8da326c6704c1335f4611d96e

# Outputs >>
# Decrypted Message ("2016-05-02T23:38:53.936Z"):
# This is a test

node index.js decrypt --priv $TEST_PRI --pub $MY_PUB 1bc089d5d64e87f2c6d1aaf170fc8330a8630eeb85dcb262b30ee465e179749e8616e4192d8acf124335f34bb49e16ac6543f36905dd9ab478bb30f57f2bc6bfd8da326c6704c1335f4611d96e

# Outputs >>
# Decrypted Message ("2016-05-02T23:38:53.936Z"):
# This is a test
```
