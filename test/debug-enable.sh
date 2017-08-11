#!/bin/sh

# enable pr_debug()
af_graft=`cd ../kmod && pwd`/af_graft.c
debugctl="/sys/kernel/debug/dynamic_debug/control"

echo -n "file $af_graft  +p"  > $debugctl
