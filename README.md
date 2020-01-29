# gmalg
## 说明
## Features
 - 一个简易算法库
 - 支持国密算法 sm1, sm2, sm3, sm4算法源码。
 - 支持通用加密算法 aes, des, rsa1024, rsa2048
 - 支持信息摘要算法 md5, sha1, sha224, sha256, sha384, sha512
 - 支持 sm3 HMAC
 - 支持C89, C99 标准, 可以移植到嵌入式系统中。

## 编译选项
## Options
### gmalg选项编译宏配置/Compile Macro

```sh
vi ./private_include/typedef.h
```

```
#define __BULID_LINUX__      /*For Linux support file system*/
/*#define __BUILD_NO_OS__*/  /*ARM with keil embed system*/

#define __LITTLE_ENDIAN__   
/*#define __BIG_ENDIAN__*/  

/*#define RANDOM_SOFTWARE*/  /*if no support "/dev/urandom" */

/*Big Numer MAX BIT, RSA max bit RSA2048*/
#define RSA_MAX_MODULUS_BITS  2048

```


### C语言标准 / C Language Standers

```sh
vi ./generic.mk
```

```sh
CFLAGS          += -shared -fPIC -Werror -O3 -std=c99    /*C99 支持变长数组*/
#CFLAGS          += -shared -fPIC -Werror -O3 -std=c89   /*C89 使用malloc/free*/

```



## 编译:
### Compile:

```sh
$ make clean
$ make
```

## 编译后，查看输出:
### Output Library:

```sh 
$ cd .obj
$ ls
$ libgmalg.a libgmalg.so
```

## 编译后，测试程序:
### Tests:
```sh 
$ cd utils/.obj
$ ls
$ sm2 sm3 sm4 rsa aes rsa key_gen
$ ./sm2
$ ./sm3
```
### gmalg 开源代码分支
### gmalg Open Source

| OpenSource | Links |
| ------ | ------ |
| c89/c99 and fixed bugs  | [https://github.com/yinggegit/gmalg][PlDa] |
| mater  | [https://github.com/zhangke5959/gmalg][PlDb] |


[//]: # (These are reference links used in the body of this note and get stripped out when the markdown processor does its job. There is no need to format nicely because it shouldn't be seen. Thanks SO - http://stackoverflow.com/questions/4823468/store-comments-in-markdown-syntax)

   [PlDa]: <https://github.com/yinggegit/gmalg>
   [PlDb]: <https://github.com/zhangke5959/gmalg>