#!/bin/sh
gcc -E exploit.c | musl-gcc -static -o exploit -xc - && gzip exploit
