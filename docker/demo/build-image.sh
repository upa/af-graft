#!/bin/bash

HIJACK_LIB=../../tools/libgraft-convert.so
WRAPPER=../../tools/graft

if [ ! -e $HIJACK_LIB ]; then
	echo "please compile tools first"
	exit 1
fi


if [ $# -lt 1 ]; then
	echo "Usage $0 [IMAGE NAME]"
	exit 1
fi

cp $HIJACK_LIB ./
cp $WRAPPER ./

docker build -t $1 .
