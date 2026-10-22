#!/bin/sh

case "$*" in
  *--bare*)
    echo "0.5.12.1"
    ;;
  *)
    echo "v0.5.12.1"
    ;;
esac
