# GmSSL-Go

## 简介

GmSSL-Go 是[GmSSL](https://github.com/guanzhi/GmSSL)密码库的Go语言封装，可以用于Go语言的应用开发。GmSSL-Go目前提供了随机数生成器、SM2加密/签名、SM3哈希、SM4加密解密、SM9加密/签名、SM2证书解析等功能，可以覆盖当前国密算法主要应用开发场景。

GmSSL-Go以`cgo`方式实现，通过Go类和方法提供了如下密码接口：

* 密码随机数生成器
* SM2加密和签名，SM2密钥生成、私钥口令加密保护、密钥PEM文件导入导出
* SM2数字证书的导入、解析和验证
* SM3哈希函数、HMAC-SM3消息认证码、基于SM3的PBKDF2密钥导出函数
* SM4分组加密，以及SM4的CBC、CTR、GCM三种加密模式
* SM9加密和签名，以及SM9密钥生成、密钥口令加密保护、密钥PEM文件导入导出
* ZUC序列密码加密

目前GmSSL-Go功能可以覆盖除SSL/TLS/TLCP之外的国密算法主要应用开发场景。

## 开发者

<a href="https://github.com/GmSSL/GmSSL-Go/graphs/contributors">
	<img src="https://contrib.rocks/image?repo=GmSSL/GmSSL-Go" />
</a>

## 上手使用

### 安装GmSSL依赖

GmSSL-Go依赖[GmSSL](https://github.com/guanzhi/GmSSL)项目，需要在编译前需要先在系统上编译、安装并测试通过GmSSL库及工具。请在[GmSSL](https://github.com/guanzhi/GmSSL)项目上下载最新的GmSSL代码，并完成编译、测试和安装。安装完毕后，即可开始使用GmSSL-Go项目。

### 在Go项目中使用GmSSL

您可以直接在新项目中使用GmSSL-Go接口，首先创建一个新项目，并初始化模块

```bash
$ mkdir hello
$ cd hello
```

```bash
$ go mod init example.com/hello
go: creating new go.mod: module example.com/hello
```


创建源文件`hello.go`

```go
package main

import (
	"fmt"
	"github.com/GmSSL/GmSSL-Go"
)

func main() {
	fmt.Println(gmssl.GetGmSSLLibraryVersion())
}
```

获取GmSSL-Go模块
```bash
$ go mod tidy
go: found gmssl in gmssl v0.0.0-00010101000000-000000000000
```

编译执行
```bash
$ go build
$ go run .
GmSSL 3.1.1 Dev
```

## 开发手册

### 随机数生成器

函数`RandBytes`实现随机数生成功能，生成的是具备密码安全性的随机数，可以用于密钥、IV或者其他随机数生成器的随机种子。

```Go
func RandBytes(length int) ([]byte, error) {
	outbuf := make([]byte, length)
	if C.rand_bytes((*C.uchar)(&outbuf[0]), C.size_t(length)) <= 0 {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:length], nil
}
```

`RandBytes`是通过调用操作系统的密码随机数生成器（如`/dev/urandom`）实现的。由于底层操作系统的限制，在一次调用`RandBytes`时不要指定明显超过密钥长度的输出长度，例如参数`length`的值不要超过128，否则可能导致阻塞，或者产生错误和异常。如果应用需要大量的随机数据，不应使用`RandBytes`，而是应该考虑其他伪随机数生成算法。

需要注意的是，`RandBytes`类的安全性依赖于底层的操作系统随机数生成器的安全性。在服务器、笔记本等主流硬件和Windows、Linux、Mac主流服务器、桌面操作系统环境上，当计算机已经启动并且经过一段时间的用户交互和网络通信后，`RandBytes`可以输出高质量的随机数。但是在缺乏用户交互和网络通信的嵌入式设备中，`RandBytes`返回的随机数可能存在随机性不足的问题，在这些特殊的环境中，开发者需要提前或在运行时检测`RandBytes`是否能够提供具有充分的随机性。

### SM3哈希

SM3密码杂凑算法可以将任意长度的输入数据计算为固定32字节长度的哈希值。


结构体`Sm3`绑定了多种Sm3方法，`NewSm3`函数返回了Sm3类型对象。

```Go

type Sm3 struct {
	sm3_ctx C.SM3_CTX
}

func NewSm3() *Sm3 
func (sm3 *Sm3) Update(data []byte) 
func (sm3 *Sm3) Digest() []byte 
func (sm3 *Sm3) Reset() 
```

下面的例子展示了如何通过类`Sm3`计算字符串的SM3哈希值。


```Go
	sm3 := gmssl.NewSm3()
	sm3.Update([]byte("abc"))
	dgst := sm3.Digest()
	fmt.Printf("Sm3('abc') : %x\n", dgst)
```

这个例子的源代码在`examples/examples.go`文件中，编译并运行这个例子。

```bash
❯ cd examples
❯ go mod init examples.com/examples
go: creating new go.mod: module examples.com/examples
go: to add module requirements and sums:
        go mod tidy
❯ go mod tidy
go: finding module for package github.com/GmSSL/GmSSL-Go
go: found github.com/GmSSL/GmSSL-Go in github.com/GmSSL/GmSSL-Go v1.3.1
❯ go build
❯ go run .
```
可以看到输出内容有：

```bash
Sm3('abc') : 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

打印出的`66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0`就是字符串`abc`的哈希值。字符串`abc`的哈希值也是SM3标准文本中给出的第一个测试数据，通过对比标准文本可以确定这个哈希值是正确的。

也可以通过`gmssl`命令行来验证`Sm3`类的计算是正确的。

```bash
$ echo -n abc | gmssl sm3
66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

可以看到输出的结果是一样。

注意，如果将字符串`abc`写入到文本文件中，文本编辑器通常会在文本结尾处增加格外的结束符，如`0x0a`字符，那么计算出的哈希值将不是上面的结果，比如可能是`12d4e804e1fcfdc181ed383aa07ba76cc69d8aedcbb7742d6e28ff4fb7776c34`。如果命令`echo`不使用`-n`的参数，也会出现同样的错误。这是很多开发者在初次进行哈希函数开发时容易遇到的错误，哈希函数的安全性质保证，即使输入的消息只差一个比特，那么输出的哈希值也完全不同。

如果需要哈希的数据来自于网络或者文件，那么应用可能需要多次读取才能获得全部的数据。在通过`Sm3`计算哈希值时，应用不需要通过保存一个缓冲区来保存全部的数据，而是可以通过多次调用`update`方法，将数据输入给`Sm3`对象，在数据全都输入完之后，最后调用`digest`方法得到全部数据的SM3哈希值。下面的代码片段展示了这一用法。

```Go
	sm3 := gmssl.NewSm3()
	sm3.Update([]byte("Hello"))
	sm3.Update([]byte("World!"))
	dgst := sm3.Digest()
	fmt.Printf("Sm3('Hello World!') : %x\n", dgst)
```

这个例子中两次调用了`update`方法，效果等同于

```Go
sm3.Update([]byte("Hello world!"))
```

注意，SM3算法也支持生成空数据的哈希值，因此下面的代码片段也是合法的。

```Go
	sm3 := gmssl.NewSm3()
	dgst := sm3.Digest()
```

GmSSL-Java其他类的`update`方法通常也都提供了这种形式的接口。在输入完所有的数据之后，通过调用`digest`方法就可以获得所有输入数据的SM3哈希值了。`digest`方法输出的是长度为`Sm3DigestSize`字节（即32字节）的二进制哈希值。

如果应用要计算多组数据的不同SM3哈希值，可以通过`reset`方法重置`Sm3`对象的状态，然后可以再次调用`update`和`digest`计算新一组数据的哈希值。这样只需要一个`Sm3`对象就可以完成多组哈希值的计算。

```Go
Sm3 sm3 = new Sm3();
sm3.update("abc".getBytes());
byte[] dgst1 = sm3.digest();

sm3.reset();
sm3.update("Hello ".getBytes());
sm3.update("world!".getBytes());
byte[] dgst2 = sm3.digest();
```

GmSSL-Go的部分其他类型也提供了`reset`方法。

### HMAC-SM3消息认证码

HMAC-SM3是基于SM3密码杂凑算法的消息认证码(MAC)算法，消息认证码算法可以看作带密钥的哈希函数，主要用于保护消息不受篡改。通信双方需要事先协商出一个密钥，比如32字节的随机字节序列，数据的发送方用这个密钥对消息计算MAC值，并且把MAC值附在消息后面。消息的接收方在收到消息后，用相同的密钥计算消息的MAC值，并且和发送消息附带的MAC值做对比，如果一致说明消息没有被篡改，如果不一致，说明消息被篡改了。

结构体`Sm3Hmac`绑定了多种基于SM3的HMAC消息认证码算法，`NewSm3Hmac`函数返回了`Sm3Hmac`类型对象。

```Go
type Sm3Hmac struct {
	sm3_hmac_ctx C.SM3_HMAC_CTX
}

func NewSm3Hmac(key []byte) (*Sm3Hmac, error) 
func (hmac *Sm3Hmac) Update(data []byte)
func (hmac *Sm3Hmac) GenerateMac() []byte 
func (hmac *Sm3Hmac) Reset(key []byte) error 
```

HMAC-SM3算法可以看作是带密钥的SM3算法，因此在生成`Sm3Hmac`对象时需要传入一个密钥作为输入参数。虽然HMAC-SM3在算法和实现上对密钥长度没有限制，但是出于安全性、效率等方面的考虑，HMAC-SM3算法的密钥长度建议采用32字节（等同于SM3哈希值的长度），不应少于16字节，采用比32字节更长的密钥长度会增加计算开销而不会增加安全性。

下面的例子显示了如何用HMAC-SM3生成消息`abc`的MAC值。

```Go
	key, _ := gmssl.RandBytes(16)
	hmac, _ := gmssl.NewSm3Hmac(key)
	hmac.Update([]byte("abc"))
	mac := hmac.GenerateMac()
	fmt.Printf("Sm3Hmac('abc') : %x\n", mac)
```

`Sm3Hmac`也通过`update`方法来提供输入消息，应用可以多次调用`update`。

应用在通过`update`完成数据输入后，调用`GenerateMac`可以获得消息认证码，HMAC-SM3输出为固定32字节，即`Sm3HmacMaxKeySize`的二进制消息认证码。

### 基于口令的密钥导出函数 PBKDF2

常用软件如Word、PDF、WinRAR等支持基于口令的文件加密，字符串形式的口令相对于随机的密钥字节序列对用户来说更容易记忆和输入，对用户更加友好。但是由于口令中存在的信息熵远低于随机的二进制密钥，直接将口令字符串作为密钥，甚至无法抵御来自个人计算机的暴力破解攻击。一种典型的错误用法是直接用哈希函数计算口令的哈希值，将看起来随机的哈希值作为密钥使用。但是由于口令的空间相对较小，攻击者仍然可以尝试所有可能口令的哈希值，对于暴力破解来说，破解口令的哈希值和原始口令，在攻击难度上没有太大差别。

安全和规范的做法是采用一个基于口令的密钥导出函数(Password-Based Key Derivation Function, PBKDF)从口令中导出密钥。通过PBKDF导出密钥并不会降低攻击者在暴力破解时尝试的口令数量，但是可以防止攻击者通过查预计算表的方式来加速破解，并且可以大大增加攻击者尝试每一个可能口令的计算时间。PBKDF2是安全的并且使用广泛的PBKDF算法标准之一，算法采用哈希函数作为将口令映射为密钥的主要部件，通过加入随机并且公开的盐值(Salt)来抵御预计算，通过增加多轮的循环计算来增加在线破解的难度，并且支持可变的导出密钥长度。

函数`Sm3Pbkdf2`实现了基于SM3的PBKDF2算法。

```Go
func Sm3Pbkdf2(pass string, salt []byte, iter uint, keylen uint) ([]byte, error) 
```

其中核心的密钥导出功能是通过`pbkdf2_hmac_sm3_genkey`方法实现的。

* `pass`用于导出密钥的用户口令。
* `salt`是用于抵御与计算的盐值。这个值需要用随机生成（比如通过`Random`类），并且具有一定的长度。Salt值不需要保密，因此在口令加密数据时，可以直接将这个值附在密文前，传输给接收方。Salt值越长，抵御预计算攻击的效果就更好。例如当Salt为8字节（64比特）长的随机值时，攻击者预计算表就要扩大$2^{64}$倍。`Sm3Pbkdf2`提供一个推荐的Salt值长度`Sm3Pbkdf2DefaultSaltSize`常量，并且在实现上不支持超过`Sm3Pbkdf2MaxSaltSize`长度的Salt值。
* `iter`参数用于表示在导出密钥时调用SM3算法的循环次数，`iter`值越大，暴力破解的难度越大，但是同时用户在调用这个函数时的开销也增大了。一般来说`iter`值的应该选择在用户可接收延迟情况下的最大值，比如当`iter = 10000`时，用户延迟为100毫秒，但是对于用户来说延迟感受不明显，但是对于暴力攻击者来说`iter = 10000`意味着攻击的开销增加了大约1万倍。`Sm3Pbkdf2`通过`Sm3Pbkdf2MinIter`和`Sm3Pbkdf2MaxIter`两个常量给出了`iter`值的范围，用户可以根据当前计算机的性能及用户对延迟的可感知度，在这个范围内选择合适的值。
* `keylen`参数表示希望导出的密钥长度，这个长度不可超过常量`Sm3Pbkdf2MaxKeySize`。

下面的例子展示了如何从口令字符串导出一个密钥。

```Go
	salt, _ := gmssl.RandBytes(gmssl.Sm3Pbkdf2DefaultSaltSize)
	kdf_key, _ := gmssl.Sm3Pbkdf2("Password", salt, gmssl.Sm3Pbkdf2MinIter, gmssl.Sm3HmacMinKeySize)
	fmt.Printf("Sm3Pbkdf2('Password') : %x\n", kdf_key)
```

### SM4分组密码

SM4算法是分组密码算法，其密钥长度为128比特（16字节），分组长度为128比特（16字节）。SM4算法每次只能加密或者解密一个固定16字节长度的分组，不支持加解密任意长度的消息。分组密码通常作为更高层密码方案的一个组成部分，不适合普通上层应用调用。如果应用需要保护数据和消息，那么应该优先选择采用SM4-GCM模式，或者为了兼容已有的系统，也可以使用SM4-CBC或SM4-CTR模式。

结构体`Sm4`绑定了多种基本的SM4分组密码算法，`NewSm4`函数返回了Sm4类型的对象。

```java
type Sm4 struct {
	sm4_key C.SM4_KEY
	encrypt bool
}

func NewSm4(key []byte, encrypt bool) (*Sm4, error) 
func (sm4 *Sm4) Encrypt(block []byte) ([]byte, error)
```

`Sm4`对象在创建时需要提供`Sm4KeySize`字节长度的密钥`key`，以及一个布尔值`encrypt`表示是用于加密还是解密。

方法`Encrypt`根据创建时的选择进行加密或解密，每次调用`Encrypt`只处理一个分组，即读入`Sm4BlockSize`长度的输入，返回16字节的结果。

下面的例子展示SM4分组加密

```Go
	block, _ := gmssl.RandBytes(gmssl.Sm4BlockSize)
	sm4_enc, _ := gmssl.NewSm4(key, true)
	cblock, _ := sm4_enc.Encrypt(block)
	fmt.Printf("SM4 Plaintext : %x\n", block)
	fmt.Printf("SM4 Ciphertext: %x\n", cblock)
```

多次调用`Sm4`的分组加密解密功能可以实现ECB模式，由于ECB模式在消息加密应用场景中并不安全，因此GmSSL中没有提供ECB模式。如果应用需要开发SM4的其他加密模式，也可可以基于`Sm4`类来开发这些模式。

### SM4-CBC加密模式

CBC模式是应用最广泛的分组密码加密模式之一，虽然目前不建议在新的应用中继续使用CBC默认，为了保证兼容性，应用仍然可能需要使用CBC模式。

结构`Sm4Cbc`绑定了多种方法，实现了SM4的带填充CBC模式，可以实现对任意长度数据的加密。注意，`Sm4Cbc`结构不支持不带填充的CBC模式。由于需要对明文进行填充，因此`Sm4Cbc`输出的密文长度总是长于明文长度，并且密文的长度是整数个分组长度。

```Go
type Sm4Cbc struct {
	sm4_cbc_ctx C.SM4_CBC_CTX
	encrypt bool
}

func NewSm4Cbc(key []byte, iv []byte, encrypt bool) (*Sm4Cbc, error) 
func (cbc *Sm4Cbc) Update(data []byte) ([]byte, error) 
func (cbc *Sm4Cbc) Finish() ([]byte, error)
func (cbc *Sm4Cbc) Reset(key []byte, iv []byte, encrypt bool) error 
```

在通过`NewSm4Cbc`函数生成Sm4Cbc类型对象时，其中`key`和`iv`都必须为16字节长度。由于CBC模式中加密和解密的计算过程不同，因此在调用`NewSm4Cbc`时，必须通过布尔值`encrypt`指定是加密还是解密。

由于`Sm4Cbc`在加解密时维护了内部的缓冲区，因此`Update`的输出长度可能不等于输入长度，应该保证输出缓冲区的长度至少比输入长度长一个`Sm4BlockSize`长度。

下面的例子显示了采用SM4-CBC加密和解密的过程。

```Go
	sm4_cbc_enc, _ := gmssl.NewSm4Cbc(key, iv, true)
	cbc_ciphertext, _ := sm4_cbc_enc.Update([]byte("abc"))
	cbc_ciphertext_last, _ := sm4_cbc_enc.Finish()
	cbc_ciphertext = append(cbc_ciphertext, cbc_ciphertext_last...)
	fmt.Printf("ciphertext = %x\n", cbc_ciphertext)
	sm4_cbc_dec, _ := gmssl.NewSm4Cbc(key, iv, false)
	cbc_plaintext, _ := sm4_cbc_dec.Update(cbc_ciphertext)
	cbc_plaintext_last, _ := sm4_cbc_dec.Finish()
	cbc_plaintext = append(cbc_plaintext, cbc_plaintext_last...)
	fmt.Printf("plaintext = %x\n", cbc_plaintext)
```

### SM4-GCM认证加密模式

SM4的GCM模式是一种认证加密模式，和CBC、CTR等加密模式的主要区别在于，GCM模式的加密过程默认在密文最后添加完整性标签，也就是MAC标签，因此应用在采用SM4-GCM模式时，没有必要再计算并添加SM3-HMAC了。在有的应用场景中，比如对消息报文进行加密，对于消息头部的一段数据（报头字段）只需要做完整性保护，不需要加密，SM4-GCM支持这种场景。

结构`Sm4Cbc`绑定了多种方法，实现了SM4算法的GCM模式，`NewSm4Gcm`函数返回了Sm4Cbc类型的对象。


```java
type Sm4Gcm struct {
	sm4_gcm_ctx C.SM4_GCM_CTX
	encrypt bool
}

func NewSm4Gcm(key []byte, iv []byte, aad []byte, taglen int, encrypt bool) (*Sm4Gcm, error) 
func (gcm *Sm4Gcm) Update(data []byte) ([]byte, error)
func (gcm *Sm4Gcm) Finish() ([]byte, error) 
func (gcm *Sm4Gcm) Reset(key []byte, iv []byte, aad []byte, taglen int, encrypt bool)
```

GCM模式和CBC、CTR、HMAC不同之处还在于可选的IV长度和MAC长度，其中IV的长度必须在`Sm4GcmMinIvSize`和`Sm4GcmMaxIvSize`之间，长度为`Sm4GcmDefaultIvSize`有最佳的计算效率。MAC的长度也是可选的，通过`NewSm4Gcm`函数中的`taglen`设定，其长度不应低于8字节，不应长于`Sm4BlockSize`即16字节。

在`NewSm4Gcm`函数中，除了`key`、`iv`,`encrypt`、`taglen`等参数，还可以提供`aad`字节数字用于提供不需要加密的消息头部数据。


下面例子展示SM4-GCM加密和解密的过程。

```Go
	sm4_gcm_enc, _ := gmssl.NewSm4Gcm(key, iv, aad, taglen, true)
	gcm_ciphertext, _ := sm4_gcm_enc.Update([]byte("abc"))
	gcm_ciphertext_last, _ := sm4_gcm_enc.Finish()
	gcm_ciphertext = append(gcm_ciphertext, gcm_ciphertext_last...)
	fmt.Printf("ciphertext = %x\n", gcm_ciphertext)
	sm4_gcm_dec, _ := gmssl.NewSm4Gcm(key, iv, aad, taglen, false)
	gcm_plaintext, _ := sm4_gcm_dec.Update(gcm_ciphertext)
	gcm_plaintext_last, _ := sm4_gcm_dec.Finish()
	gcm_plaintext = append(gcm_plaintext, gcm_plaintext_last...)
	fmt.Printf("plaintext = %x\n", gcm_plaintext)
```

通过上面的例子可以看出，SM4-GCM加密模式中可以通过`NewSm4Gcm`指定了一个不需要加密的字段`aad`，注意`aad`是不会在`Update`中输出的。由于GCM模式输出额外的完整性标签，因此`Update`和`Finish`输出的总密文长度会比总的输入明文长度多`taglen`个字节。


### Zuc序列密码

祖冲之密码算法(ZU Cipher, ZUC)是一种序列密码，密钥和IV长度均为16字节。作为序列密码ZUC可以加密可变长度的输入数据，并且输出的密文数据长度和输入数据等长，因此适合不允许密文膨胀的应用场景。在国密算法体系中，ZUC算法的设计晚于SM4，在32位通用处理器上通常比SM4-CBC明显要快。

在安全性方面，不建议在一组密钥和IV的情况下用ZUC算法加密大量的数据（比如GB级或TB级），避免序列密码超长输出时安全性降低。另外ZUC算法本身并不支持数据的完整性保护，因此在采用ZUC算法加密应用数据时，应考虑配合HMAC-SM3提供完整性保护。ZUC的标准中还包括针对移动通信底层数据报文加密的128-EEA3方案和用于消息完整性保护的128-EIA3算法，目前GmSSL-Java中不支持这两个算法。

结构体`Zuc`绑定了ZUC加密、解密功能的接口，`NewZuc`函数可以返回Zuc类型的对象。

```Go
type Zuc struct {
	zuc_ctx C.ZUC_CTX
}

func NewZuc(key []byte, iv []byte) (*Zuc, error) 
func (zuc *Zuc) Update(in []byte) ([]byte, error)
func (zuc *Zuc) Finish() ([]byte, error) 
```

`Zuc`结构的接口说明如下：

* 序列密码通过生成密钥序列和输入数据进行异或操作的方式来加密或解密，因此序列密码的加密和解密的过程一致，因此`NewZuc`函数不需要格外的参数表明加密还是解密。
* 由于CTR模式实际上是以分组密码实现了序列密码的能力，因此可以发现`Zuc`和`Sm4Cbc`的接口是完全一致的。
* ZUC算法内部实现是以32比特字（4字节）为单位进行处理，因此`Zuc`实现加解密过程中也有内部的状态缓冲区，因此`Update`的输出长度可能和输入长度不一致，调用方应该保证输出缓冲区长度比输入长度长4个字节。

下面的例子展示了`Zuc`的加密和解密过程。

```Go
	zuc, _ := gmssl.NewZuc(key, iv)
	zuc_ciphertext, _ := zuc.Update([]byte("abc"))
	zuc_ciphertext_last, _ := zuc.Finish()
	zuc_ciphertext = append(zuc_ciphertext, zuc_ciphertext_last...)
	zuc, _ = gmssl.NewZuc(key, iv)
	zuc_plaintext, _ := zuc.Update(zuc_ciphertext)
	zuc_plaintext_last, _ := zuc.Finish()
	zuc_plaintext = append(zuc_plaintext, zuc_plaintext_last...)
	fmt.Printf("plaintext = %x\n", zuc_plaintext)
```

### SM2

SM2是国密标准中的椭圆曲线公钥密码，包含数字签名算法和公钥加密算法。SM2相关的功能由结构`Sm2Key`和`Sm2Signature`实现，其中`Sm2Key`绑定了SM2密钥对的生成、基础的加密和签名方案，`Sm2Signature`结构绑定了对任意长度消息签名的签名方案。

```Go
type Sm2Key struct {
	sm2_key C.SM2_KEY
	has_private_key bool
}
func GenerateSm2Key() (*Sm2Key, error) 
func ImportSm2EncryptedPrivateKeyInfoPem(pass string, path string) (*Sm2Key, error)
func ImportSm2PublicKeyInfoPem(path string) (*Sm2Key, error)
func (sm2 *Sm2Key) ExportEncryptedPrivateKeyInfoPem(pass string, path string) error
func (sm2 *Sm2Key) ExportPublicKeyInfoPem(path string) error
func (sm2 *Sm2Key) ComputeZ(id string) ([]byte, error) 
func (sm2 *Sm2Key) Sign(dgst []byte) ([]byte, error)
func (sm2 *Sm2Key) Verify(dgst []byte, signature []byte) bool 
func (sm2 *Sm2Key) Encrypt(in []byte) ([]byte, error)
func (sm2 *Sm2Key) Decrypt(in []byte) ([]byte, error)

type Sm2Signature struct {
	sm2_sign_ctx C.SM2_SIGN_CTX
	sign bool
}
func NewSm2Signature(sm2 *Sm2Key, id string, sign bool) (*Sm2Signature, error) 
func (sig *Sm2Signature) Update(data []byte) error 
func (sig *Sm2Signature) Sign() ([]byte, error) 
func (sig *Sm2Signature) Verify(signature []byte) bool 
```

可以通过`GenerateSm2Key`方法生成一个新的密钥对，或者通过导入函数从外部导入密钥。`Sm2Key`一共提供了2个不同的导入方法：

* `ImportSm2EncryptedPrivateKeyInfoPem` 从加密的PEM文件中导入SM2私钥，因此调用时需要提供PEM文件的路径和解密的口令(Password)。
* `ImportSm2PublicKeyInfoPem`从PEM文件中导入SM2公钥，只需要提供文件的路径，不需要提供口令。

上面2个导入函数也都有对应的导出函数。从PEM文件中导入导出公钥私钥和`gmssl`命令行工具的默认密钥格式一致，并且在处理私钥时安全性更高，建议在导入导出私钥时采用加密的PEM文件格式。

下面的代码片段展示了`Sm2Key`私钥的加密导出和导入。

```Go
	sm2, _ := gmssl.GenerateSm2Key()
	sm2.ExportEncryptedPrivateKeyInfoPem("Password", "sm2.pem")
	sm2pri, _ := gmssl.ImportSm2EncryptedPrivateKeyInfoPem("Password", "sm2.pem")
```


下面的代码片段展示了`Sm2Key`公钥的导出和导入。

```Go
	sm2, _ := gmssl.GenerateSm2Key()
	sm2.ExportPublicKeyInfoPem("sm2pub.pem")
	sm2pub, _ := gmssl.ImportSm2PublicKeyInfoPem("sm2pub.pem")
```

导出的`sm2pub.pem`公钥文件是一个标准的PKCS #8 EncryptPrivateKeyInfo类型并且PEM编码的私钥文件格式，`openssl pkeyutil`命令行工具也默认采用这个格式的私钥，但是由于GmSSL在私钥文件中采用SM4-CBC、HMAC-SM3组合加密了SM2的私钥，因此对于默认使用3DES的`openssl`等工具可能无法解密这个私钥（即使这个工具包含SM2算法的实现）。由于公钥文件是不加密的，因此这个公钥可以被支持SM2的第三方工具、库打开和访问。

`Sm2Key`绑定了`ComputeZ`、`Sign`、`Verify`、`Encrypt`、`Decrypt`这几个密码计算相关的方法。

其中`ComputeZ`是由公钥和用户的字符串ID值计算出一个称为“Z值”的哈希值，用于对消息的签名。由于`Sm2Signature`结构体绑定了了SM2消息签名的完整功能，因此这个`ComputeZ`方法只是用于实验验证。由于这个计算只需要公钥，因此如果密钥值是通过`ImportSm2PublicKeyInfoPem`导入的，也可以成功计算出32字节的哈希值结果。

```Go
	z, _ := sm2pub.ComputeZ(gmssl.Sm2DefaultId)
	fmt.Printf("Z = %x\n", z)
	Z, _ := sm2pri.ComputeZ(gmssl.Sm2DefaultId)
	fmt.Printf("Z = %x\n", Z)
```

`Sign`和`Verify`方法实现了SM2签名的底层功能，这两个方法不支持对数据或消息的签名，只能实现对SM3哈希值的签名和验证，并没有实现SM2签名的完整功能。应用需要保证调用时提供的`dgst`参数的字节序列长度为32。只有密码协议的底层开发者才需要调用`ComputeZ`、`Sign`、`Verify`这几个底层方法。

```Go
	signature, _ := sm2pri.Sign(dgst)
	fmt.Printf("Signature = %x\n", signature)
	ret := sm2pub.Verify(dgst, signature)
	fmt.Print("Verify success = ", ret, "\n")
```

`Encrypt`和`Decrypt`方法实现了SM2加密和解密功能。注意，虽然SM2标准中没有限制加密消息的长度，但是公钥加密应该主要用于加密较短的对称密钥、主密钥等密钥数据，因此GmSSL库中限制了SM2加密消息的最大长度。应用在调用`Encrypt`时，需要保证输入的明文长度不超过`Sm2MaxPlaintextSize`的限制。如果需要加密引用层的消息，应该首先生成对称密钥，用SM4-GCM加密消息，再用SM2加密对称密钥。

```Go
	sm2_ciphertext, _ := sm2pub.Encrypt([]byte("abc"))
	sm2_plaintext, _ := sm2pri.Decrypt(sm2_ciphertext)
	fmt.Printf("SM2 Ciphertext : %x\n", sm2_ciphertext)
	fmt.Printf("SM2 Plaintext : %s\n", sm2_plaintext)
```