{
  "targets": [
    {
      "target_name": "decryptor",
      "sources": ["src/decryptor.cc"],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "libraries": [
        "-lssl",
        "-lcrypto"
      ],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"],
      "xcode_settings": {
        "GCC_ENABLE_CPP_EXCEPTIONS": "NO",
        "CLANG_CXX_LIBRARY": "libc++",
        "MACOSX_DEPLOYMENT_TARGET": "10.10",
        "OTHER_CPLUSPLUSFLAGS": ["-std=c++11", "-O3"]
      },
      "msvs_settings": {
        "VCCLCompilerTool": {
          "ExceptionHandling": 0,
          "Optimization": 2,
          "FavorSizeOrSpeed": 1,
          "OmitFramePointers": 1,
          "EnableFunctionLevelLinking": 1,
          "EnableIntrinsicFunctions": 1,
          "AdditionalOptions": ["/GL"]
        },
        "VCLinkerTool": {
          "LinkTimeCodeGeneration": 1,
          "GenerateDebugInformation": false
        }
      }
    }
  ]
}
