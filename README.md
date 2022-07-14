用以解密当前（2022.7）最新版本 Windows 微信的加密数据库。

### 编译方法：

```
cl .\main.cc .\decrypt.cc .\keyleak.cc -o decrypt.exe
```

### 使用方法：

```
.\decrypt.exe [your encrypted db path] [output db path]
```

### 示例：

首先启动微信，登录后，执行
```
.\decrypt.exe "C:\Users\<Your Computer User Name>\Documents\WeChat Files\<Your WX id>\Msg\Multi\MSG0.db" <output db path>
```
然后点击一下某个聊天窗口即可解密，将解密后的数据库输出到指定的位置

### 实现方法：

非常的朴素的方法，实现一个简易 debugger，attach 到微信进程上，在 sqlcipher_page_cipher 上下断点，断下后读取出 read_ctx 结构体的值，获取到加密 key。然后直接调用微信 dll 中的 sql 操作函数。

### 存在的问题：

唯一的加密 key 是一个 64bit 的 key。在加解密时会 derive 到真正的加密 key，这个时候似乎有根据数据库加盐还是什么的，会存在多种 read_ctx，所以拿到的 ctx 只能解密一部分数据库。就会存在解密失败的情况。

同时如果所有的文件都缓存在了内存里面（微信使用了比较长的时间下），可能就抓不到函数执行了。

## 郑重声明

*仅供研究学习使用，任何人使用此仓库做的任何非法操作都与本人无关！*
