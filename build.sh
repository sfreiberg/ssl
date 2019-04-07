#!/bin/bash

for OS in darwin linux freebsd openbsd windows
do
    if [ "$OS" == "windows" ]; then
        GOOS=$OS go build -o ssl_$OS.exe
    else
        GOOS=$OS go build -o ssl_$OS
    fi
done