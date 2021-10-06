Netcat with AES
- In plain type, it can work with normal netcat.
- In AES type, the transfer data encrypted with AES. Make it safe in transfer.

可以使用 AES 加密的 netcat。
- 在明文模式，可以和经典 netcat 配合使用。
- 在加密模式，使用AES对传输内容进行加密，保证传输安全。

# build
```sh
sudo apt install libssl-dev
make
```

# usage
```txt
ncs [-s passwd] -l port
ncs [-s passwd] host port
```