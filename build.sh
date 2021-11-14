#!/usr/bin/bash

check-err()
{
    if [ $? -ne 0 ] ; then
        echo "ERROR: $1"
        echo "Aborting."
        exit 1
    fi
}

cargo build
check-err "Rust build failed."

TMPFILE=$(mktemp)
OUTFILE=c-api/main.h
cbindgen --cpp-compat --lang c++ -o "$TMPFILE"
check-err "Could not generate C++ bindings."

cat <<EOF > "$OUTFILE"
#pragma once

EOF
check-err "Could not build header file."

cat $TMPFILE >> $OUTFILE
check-err "Could not build header file."

g++ -g -o target/main c-api/main.cpp target/debug/libwai_me.a -lpthread -ldl -lm
check-err "Compilation error."

