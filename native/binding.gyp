{
  "targets": [
    {
      "target_name": "decryptor",
      "sources": ["src/decryptor.cc"],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS",
        "NAPI_VERSION=3"
      ],
      "conditions": [
        ['OS=="win"', {
          "msvs_settings": {
            "VCLinkerTool": {
              "AdditionalOptions": ["/EXPORT:napi_register_module_v1"]
            }
          }
        }]
      ]
    }
  ]
}
