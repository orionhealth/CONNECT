#!/bin/sh

getent group orion &>/dev/null || groupadd -r orion -g 2134 &>/dev/null
getent passwd orion &>/dev/null || \
  useradd -r -u 2134 -g orion -d /opt -s /sbin/nologin \
  -c "connect" orion &>/dev/null
