# to-wit: A C/C++ WIT Parser

**Attention**: The code in this repository is intended for experimental use only and is not fully tested, documented, or supported by SingleStore. Visit the [SingleStore Forums](https://www.singlestore.com/forum/) to ask questions about this repository.

This library provides an C-based FFI wrapper around the
[wit-bindgen](https://github.com/bytecodealliance/wit-bindgen) parsing
API (written natively in Rust).  It enables C/C++ programs to parse WIT specs 
and extract information about the their ASTs.

## Building

Just run:

   ```bash
   make all
   ```

If you need to, you can update the paths at the top of the Makefile.  The 
following will be generated:

   * `target/debug/*` - Debug libs
   * `target/release/*` - Release libs
   * `target/to-wit.h` - Generated header file
   * `target/to-wit` - Example program

## Usage

Just copy the `target/to-wit.h` file to wherever you want and `#include` it.  
You'll also need to make sure you link against `target/release/libto_wit.a` or 
`target/release/libto_wit.so`.

See the `target/to-wit` target in the Makefile for a simple example.

## Example

An example driver program is included, called `to-wit`.  Its C source can be 
found in the `example` directory.  To build it, run `make example`.

While it is intended primarily as an example, it is also useful in its own 
right.  It will output parsed info about a WIT spec.  It has two modes --
summary and detail.

To get a summary of the exports available in a WIT spec, run it like this:

    target/to-wit example/example.wit

You'll get this back:

    Functions:
      sentiment
      square
      split
      hilbert_encode

To get detailed ABI information about one of the exports, run it like this:

    target/to-wit example/example.wit sentiment

And you'll get this back:

    Func Name: sentiment
    Signature:
      Params: [I32, I32]
      Result: [I32]
      RetPtr: [F64, F64, F64, F64]
    Params:
      [name=input, type=List, size=8, align=4]
        [name=, type=Char, size=4, align=4]
    Results:
      [name=, type=Record, size=32, align=8]
        [name=compound, type=F64, size=8, align=8]
        [name=positive, type=F64, size=8, align=8]
        [name=negative, type=F64, size=8, align=8]
        [name=neutral, type=F64, size=8, align=8]

## Issues

The WIT spec is parsed as a set of guest Exports.  There is currently no
switch to make it parse the spec as Imports, although an easy workaround is to 
flip the constant `abi::AbiVariant::GuestExport` to 
`abi::AbiVariant::GuestImport` in the source file.

## Resources

* [wit-bindgen](https://github.com/bytecodealliance/wit-bindgen)

