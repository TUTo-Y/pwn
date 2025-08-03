#include <iostream>
#include <string>
#include "demo.pb.h"

using namespace std;

void backdoor()
{
    execve("/bin/sh", NULL, NULL);
}

void success(demo_pack::demo_msg &msg)
{
    char buf[0x10];
    memcpy(buf, msg.str().data(), msg.size());
}

int main()
{
    string s;
    demo_pack::demo_msg msg;

    // 读取msg字符串
    size_t s_len = 0;
    cin >> s_len;
    s.resize(s_len);
    cin.ignore().read(s.data(), s_len);

    // 反序列化
    if (true == msg.ParseFromString(s))
    {
        cout << "successfully." << endl;
        success(msg);
    }
    else
    {
        cout << "Failed" << endl;
    }

    return 0;
}