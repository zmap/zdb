zdb
===

Backend database for Internet-wide scans.

### Prereqs

On OS X:

```
$ git submodule update --init
$ brew tap grpc/grpc
$ brew uninstall protobuf
$ brew install grpc/grpc/grpc Judy rocksdb gflags python libmaxminddb
$ brew install librdkafka --HEAD
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

