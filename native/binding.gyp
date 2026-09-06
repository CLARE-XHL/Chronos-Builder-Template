{
  "targets": [
    {
      "target_name": "decryptor",
      "sources": ["src/decryptor.cc"],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "conditions": [
        ["OS==\"win\"", {
          "include_dirs": [
            "C:/Program Files/OpenSSL-Win64/include"
          ],
          "libraries": [
            "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD/libssl.lib",
            "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD/libcrypto.lib"
          ]
        }]
      ]
    }
  ]
}
