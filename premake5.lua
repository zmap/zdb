solution "zdb"
    targetdir (".")

    newoption {
        trigger = 'debug-validation',
        description = "Log changes during certificate validation jobs (deprecated)"
    }

    configurations { "Debug", "Release" }

    if _OPTIONS["debug-validation"] then
        defines { "VALIDATION_DEBUG" }
    end

    filter { "configurations:Debug" }
        defines { "DEBUG" }
        symbols "On"

    filter { "configurations:Release" }
        optimize "On"

    filter { "system:macosx" }
        sysincludedirs {
            "/usr/local/include",
            "/usr/local/opt/openssl/include",
            "/usr/local/opt/librdkafka/include"
        }
        libdirs {
            "/usr/local/opt/openssl/lib",
            "/usr/local/opt/librdkafka/lib",
            "/usr/local/lib",
            "bin/osx"
        }

    filter { "system:macosx", "language:C++" }
        buildoptions "-std=c++11 -stdlib=libc++"
        linkoptions "-stdlib=libc++"

    filter { "system:linux" }
        libdirs { "bin/linux", "/usr/local/lib"  }
        linkoptions "-pthread"

    filter { "system:linux", "language:C++" }
        buildoptions "-std=c++11"

    filter { "system:linux", "language:C" }
        buildoptions "-std=c99"

    project "gtest"
        language "C++"
        kind "StaticLib"

        includedirs { "include", "vendor/gtest" }
        files { "vendor/gtest/src/*.cc", "vendor/gtest/src/*.h"}
        removefiles { "vendor/gtest/src/gtest_main.cc" }

    project "cachehash"
        language "C"
        kind "StaticLib"
        includedirs { "vendor/cachehash", "/usr/local/include" }
        files { "vendor/cachehash/*.c", "vendor/cachehash/*.h" }

    project "iptree"
        language "C"
        kind "StaticLib"
        includedirs { "vendor/iptree", "/usr/local/include" }
        files { "vendor/iptree/*.c", "vendor/iptree/*.h" }

    project "zdb"
        kind "ConsoleApp"
        language "C++"
        files {
            "src/**.cc",
            "src/**.h",
            "vendor/base64/*.cpp",
            "vendor/base64/*.h",
	    "vendor/jsoncpp/*.cpp",
	    "vendor/jsoncpp/*.h",
            "zsearch_definitions/*.cc",
            "zsearch_definitions/*.h"
        }
        removefiles { "src/**_test.cc", "src/**_test.h", "src/test_**.h", "src/test_**.cc" }
        sysincludedirs { "include" }
        includedirs { "." , "src" , "zsearch_definitions" }
        links {
            "cachehash",
            "crypto",
            "iptree",
            "gflags",
            "gpr",
            "grpc",
            "grpc++",
            "Judy",
            "maxminddb",
            "protobuf",
            "rdkafka",
            "rdkafka++",
            "rocksdb",
            "snappy",
            "ssl",
            "z",
            "zmaplib"
        }

    project "zdb-test"
        kind "ConsoleApp"
        language "C++"
        files {
            "src/**.cc",
            "src/**.h",
            "vendor/base64/*.cpp",
            "vendor/base64/*.h",
            "vendor/jsoncpp/*.cpp",
            "vendor/jsoncpp/*.h",
            "zsearch_definitions/*.h",
            "zsearch_definitions/*.cc"
        }
        removefiles { "src/zdb_server.cc" }

        sysincludedirs { "include" }
        includedirs { ".", "src", "zsearch_definitions" }

        links {
            "cachehash",
            "crypto",
            "iptree",
            "gflags",
            "gpr",
            "grpc",
            "grpc++",
            "gtest",
            "Judy",
            "maxminddb",
            "protobuf",
            "rdkafka",
            "rdkafka++",
            "rocksdb",
            "snappy",
            "ssl",
            "z",
            "zmaplib"
        }

