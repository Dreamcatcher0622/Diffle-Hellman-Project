### README

本项目是哈尔滨工业大学（威海）网络空间安全专业的课程设计，主要包括对Diffle-Hellman协议的实现、中间人模拟攻击和使用PKI、PSK进行改进的模拟代码。
请在Linux（ubuntu）下运行本代码，并配置好相关环境及编译器。需要安装OpenSSL。所引用的库函数如下：

```c++
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cmath>
#include <cerrno>
#include <cstring>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <future>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
```

include文件夹下是工具代码，包括工具函数、Diffle-Hellman协议实现、AES256-GCM实现源文件。

最外层目录下包括客户端源代码client.cpp及可执行文件client，服务器源代码server.cpp及可执行文件server，中间人源代码middle.cpp及可执行文件middle。没有对Diffle-Hellman协议进行改进，中间人可以进行劫持。

首先启动中间人：

```shell
./middle
```

接着启动服务器监听：

```shell
./server
```

最后启动客户端：

```shell
./client
```

pki文件夹下是使用数字证书进行改进后的代码，可以防范中间人。启动方式同上。

psk文件夹下是使用预共享密钥进行改进后的代码，可以防范中间人。启动方式同上。



如果要修改cpp源代码，请在当前文件夹下重新编译可执行文件：

```shell
g++ server.cpp -o server -lssl -lcrypto
g++ client.cpp -o client -lssl -lcrypto
g++ middle.cpp -o middle -lssl -lcrypto
```

