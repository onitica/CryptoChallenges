#!/bin/bash

openssl aes-128-ecb -d -in challenge7.txt -K "59454c4c4f57205355424d4152494e45" -iv 0 -nosalt -base64

