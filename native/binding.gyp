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
      "library_dirs": [
        "$(VCPKG_ROOT)/installed/x64-windows/lib"
      ],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"]
    }
  ]
}
