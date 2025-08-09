- [基于protobuf的序列化和反序列化](#基于protobuf的序列化和反序列化)
  - [安装](#安装)
    - [protobuf的安装](#protobuf的安装)
    - [protobuf-c](#protobuf-c)
    - [pbtk](#pbtk)
  - [创建.proto文件](#创建proto文件)
    - [字段基数](#字段基数)
    - [数据类型](#数据类型)
  - [编译.proto文件](#编译proto文件)
  - [工具提取.proto文件](#工具提取proto文件)
    - [google protobuf](#google-protobuf)
    - [protobuf\_c](#protobuf_c)
  - [手动提取.proto文件](#手动提取proto文件)
  - [proto的使用](#proto的使用)
    - [python](#python)
    - [cpp](#cpp)
    - [c](#c)

# 基于protobuf的序列化和反序列化

## 安装

### protobuf的安装

在[protobuf仓库](https://github.com/protocolbuffers/protobuf)下载最新发布版本 (也可以直接git clone)

```sh
mkdir build
cd build
cmake ..
make
sudo make install
```

### protobuf-c

在[protobuf-c仓库](https://github.com/protobuf-c)下载最新发布版本

```sh
./configure
make
sudo make install
```

### pbtk

```sh
git clone git@github.com:marin-m/pbtk.git
cd pbtk
./extractors/from_binary.py ./pwn ./
```

## 创建.proto文件

```proto
// demo.proto

/**
 *  根据不同的proto版本，可以使用proto2和proto3
 *  或者使用edition = "2023";
 *  如果未指定 edition 或 syntax, 协议缓冲区编译器将假定您正在使用 proto2
 */
syntax = "proto2"; 

// 导入其他.proto
//import "proto/other_protos.proto";

package demo_pack; // 包名声明符

// 枚举
enum gender {
  man = 0;
  woman = 1;
}

// 消息
message demo_msg {
    /**
     * 每个字段的修饰符默认是 singular，一般省略不写
     * 每个字符 =后面的数字称为标识符，每个字段都需要提供一个唯一的标识符。标识符用来在消息的二进制格式中识别各个字段，一旦使用就不能够再改变。
     */
    optional string name = 1;
    required int32 id = 2;
    repeated string email = 3;
    optional gender ged = 4;
}
```

### 字段基数

__optional（推荐）__ : 一个 optional 字段有两种可能的状态：
- 字段已设置，包含一个通过显式设置或从传输中解析而来的值。它将被序列化到传输中。
- 字段未设置，将返回默认值。它不会被序列化到传输中。

__required(不要使用)__ : 必填字段, 当它确实使用时, 格式良好的消息必须且仅有一个此字段。已从 proto3 和 editions 中移除。

__repeated__ : 这种字段类型在格式良好的消息中可以重复零次或多次。重复值的顺序将得到保留。可以看作是在传递一个数组的值。

__map__ : 这是一种键/值对字段类型。

### 数据类型

| Proto | 类型| 备注 |
|  :----:  | ----  | ---- |
| double | 双精度浮点数 |
| float |	单精度浮点数 |
| int32 | 使用变长编码。对负数编码效率低下 – 如果您的字段很可能包含负值，请改用 sint32 |
| int64 | 使用变长编码。对负数编码效率低下 – 如果您的字段很可能包含负值，请改用 sint64 |
| uint32 | 使用变长编码 |
| uint64 | 使用变长编码 |
| sint32 | 使用变长编码。有符号整型值。这些比常规 int32 更有效地编码负数 |
| sint64 | 使用变长编码。有符号整型值。这些比常规 int64 更有效地编码负数 |
| fixed32 | 始终是四个字节。如果值经常大于 228，比 uint32 更高效 |
| fixed64 | 始终是八个字节。如果值经常大于 256，比 uint64 更高效 |
| sfixed32 | 始终是四个字节 |
| sfixed64 | 始终是八个字节 |
| bool | 布尔 |
| string | 字符串必须始终包含 UTF-8 编码或 7 位 ASCII 文本，且长度不能超过 232 |
| bytes | 可以包含任意字节序列，长度不超过 232 |

| Proto | C++ | Java/Kotlin | Python | Go | Ruby | C# | PHP | Dart | Rust|
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| double | double | double | float | float64 | Float | double | float | double | f64 |
| float | float | float | float | float32 | Float | float | float | double | f32 |
| int32 | int32_t | int | int | int32 | Fixnum 或 Bignum (根据需要) | int | integer | int | i32 |
| int64 | int64_t | long | int/long | int64 | Bignum | long | integer/string | Int64 | i64 |
| uint32 | uint32_t | int | int/long | uint32 | Fixnum 或 Bignum (根据需要) | uint | integer | int | u32 |
| uint64 | uint64_t | long | int/long | uint64 | Bignum | ulong | integer/string | Int64 | u64 |
| sint32 | int32_t | int | int | int32 | Fixnum 或 Bignum (根据需要) | int | integer | int | i32 |
| sint64 | int64_t | long | int/long | int64 | Bignum | long | integer/string | Int64 | i64 |
| fixed32 | uint32_t | int | int/long | uint32 | Fixnum 或 Bignum (根据需要) | uint | integer | int | u32 |
| fixed64 | uint64_t | long | int/long | uint64 | Bignum | ulong | integer/string | Int64 | u64 |
| sfixed32 | int32_t | int | int | int32 | Fixnum 或 Bignum (根据需要) | int | integer | int | i32 |
| sfixed64 | int64_t | long | int/long | int64 | Bignum | long | integer/string | Int64 | i64 |
| bool | bool | boolean | bool | bool | TrueClass/FalseClass | bool | boolean | bool | bool |
| string | string | String | str/unicode | string | String (UTF-8) | string | string | String | ProtoString |
| bytes | string | ByteString | str (Python 2), bytes (Python 3) | byte | String (ASCII-8BIT) | ByteString | string | List |ProtoBytes |

## 编译.proto文件

```
protoc  --c_out=./ ./demo.proto

        --c_out=OUT_DIR         产生C头文件和源文件
        --cpp_out=OUT_DIR       产生C++头文件和源文件
        --csharp_out=OUT_DIR    产生C#源文件
        --java_out=OUT_DIR      产生Java源文件
        --javanano_out=OUT_DIR  产生Java Nano源文件
        --js_out=OUT_DIR        产生JavaScript源文件
        --objc_out=OUT_DIR      产生Objective C头文件和源文件
        --php_out=OUT_DIR       产生PHP源文件
        --python_out=OUT_DIR    产生Python源文件
        --ruby_out=OUT_DIR      产生Ruby源文件
```

## 工具提取.proto文件

### google protobuf

使用 `pbtk` 的 `extractors/from_binary.py` 提取 pwn 中的 .proto:

```sh
./extractors/from_binary.py ./pwn ./
```

设置好环境后:

```sh
extract_proto ./pwn ./
```

### protobuf_c

使用我的工具提取

extract_proto_c -f ./pwn -d . -n default

## 手动提取.proto文件

懒得写了，直接用工具方便

## proto的使用

### python

构造msg (string类型必须为utf-8编码，注意不能有非utf-8字符，可以使用bytes类型)

```python
# demo_pb2为python文件名 demo_msg为消息名
msg = demo_pb2.demo_msg()

# 直接对对象赋值
msg.str = b'a' * 0x18 + rop_chain
msg.size = 0x18 + len(rop_chain)

# 序列化
payload = msg.SerializeToString()
# 或
payload = msg.SerializeToOstream()
```
### cpp

```C++
// demo_pack为包名 demo_msg为消息名
demo_pack::demo_msg msg;

// 补全可以理解大部分内容
// 解析
msg.ParseFromString(s)
// 或者
msg.ParseFromArray(s)
```

### c

```C
// 我也没懂这怎么命名的
DemoPack__DemoMsg *msg = NULL;

// 解包
demo_pack__demo_msg__unpack(NULL, s_len, s);
```