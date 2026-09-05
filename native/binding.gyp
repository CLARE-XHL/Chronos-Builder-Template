{
  "targets": [
    {
      "target_name": "decryptor",
      "sources": ["src/decryptor.cc"],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "libraries": [
        "-llibssl",
        "-llibcrypto"
      ],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"]
    }
  ]
}
