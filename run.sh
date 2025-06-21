#!/bin/bash

gcc -c ./sample.c -o sample.o
gcc ./main.c sample.o -o run -lcurl -lcrypto -lssl

if [ $? -ne 0 ]; then
    echo "编译失败，请检查文件路径或依赖库是否安装。"
    exit 1
fi

chmod +x run

file="$1"
result=$(./run "$file" | jq -r '.Response.TargetText')
echo "$result"
