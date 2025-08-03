# protobuf_c

## 编写protobuf_c

1. 创建 `.proto` 文件
2. 写入包的信息，如:[ctf.proto](./ctf.proto)
3. 创建对应的 `.c` 和 `.h` 文件后编译即可，命令如下:

```sh
protoc --c_out=./ ./ctf.proto
protoc --python_out=./ ./ctf.proto
```

## 反序列化protobuf_c

1. 加载`./protobuf-c/protobuf-c.h`文件的所有结构体到IDA
2. 在IDA找到`ProtobufCMessageDescriptor`结构体，通常为`protobuf_c_message_unpack`第一个参数指向的地址

其中`name`为包名, `n_fields` 和 `fields` 分别表示数据个数和内容

根据 `fields` 找到所有的数据格式 `ProtobufCFieldDescriptor`

其中 `type` 表示数据类型，详情见 `ProtobufCType`
