zdb
===

Backend database for Internet-wide scans.

### Prereqs

On OS X:

```
$ git submodule update --init
$ brew tap zmap/homebrew-formula
$ brew update
$ brew uninstall google-protobuf protobuf grpc grpc/grpc/grpc
$ brew install gflags libmaxminddb
$ brew install openssl zmap/formula/grpc@1.2 zmap/formula/protobuf@3.2
$ brew install zmap/formula/judy
$ brew install snappy lz4 zmap/formula/rocksdb@3.10
$ brew install librdkafka
$ tools/osx/premake5 gmake
$ make
```

### Building

The build system for ZDB is premake. The basic idea behind premake is to run `premake5 [target]` from the root of the ZDB repo, e.g. `premake5 gmake` to generate a Makefile. Then run `make` to actually build the executable.

The `premake5` executable is stored in the `tools/<platform>` directory, e.g. `tools/linux` for Linux and `tools/osx` for Mac OS X.

#### Examples:

**OS X**: Generate an Xcode project and open in Xcode
```
$ tools/osx/premake5 xcode4
$ open zdb.xcworkspace
```

**OX X**: Generate a Makefile and build
```
$ tools/osx/premake5 gmake
$ make
```

**Linux**: Generate a Makefile and build
```
$ tools/linux/premake5 gmake
$ make
```

### Developing

ZDB follows the Chromium style-guide. We provide a [configuration file](/.clang-format) for `clang-format`.
