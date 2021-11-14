#!/usr/bin/bash

check-err()
{
    if [ $? -ne 0 ] ; then
        echo "ERROR: $1"
        echo "Aborting."
        exit 1
    fi
}

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

g++ -g -o main c-api/main.cpp target/debug/libwitx_wrapper.a -lpthread -ldl -lm
check-err "Compilation error."

