Rust idiomatic API for OpenBSD's authentication library

## Requirements

- libclang.so (clang development library)
- Rust 1.51+

Building the crate requires bindings to authentication functions in OpenBSD's `libc`.

## Building

The low-level crate [bsd_auth-sys](https://github.com/orvij/bsd_auth-sys) includes the necessary bindings for the authentication API.

If the clang development libaries aren't present on your OpenBSD system, you will need to compile clang from source, install the libaries, and create a symbolic link to `libclang.so.*` at `/usr/lib/libclang.so`.
