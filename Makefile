##################################################################
# Config
##################################################################

# Set default shell to use in this file.
SHELL := /usr/bin/env bash

# If `cargo` is not in your path, set it explicitly here.
CARGO := /usr/bin/env cargo

# If `cbindgen` is not in your path, set it explicitly here.
CBINDGEN := /usr/bin/env cbindgen

# If `g++` is not in your path, set it explicitly here.
CPP := /usr/bin/env g++

##################################################################
# Targets
##################################################################

all: libs header example

libs: lib-release lib-debug

lib-release:
	@$(CARGO) build --release

lib-debug:
	@$(CARGO) build

header: target/to-wit.h

example: target/to-wit

target/to-wit.h:
	@$(eval TMPFILE := $(shell mktemp))
	@$(CBINDGEN) --cpp-compat --lang c++ -o "$(TMPFILE)"
	@echo "#pragma once" > target/to-wit.h
	@cat "$(TMPFILE)" >> target/to-wit.h
	@rm -f "$(TMPFILE)"
	
target/to-wit: lib-debug header
	@$(CPP) -g -o target/to-wit example/main.cpp target/debug/libto_wit.a -Itarget -lpthread -ldl -lm

clean:
	@rm -rf target

.PHONY: all libs lib-release lib-debug header clean

