{
  "variables": {
    "GAME_VERSION%": "2.2.0",
    "RELEASE_DATE%": "2026-01-01",
    "SEED_A%": "REPLACE_ME",
    "SEED_B%": "_WITH_RANDOM",
    "SEED_C%": "_SEED_IN_",
    "SEED_D%": "ACTIONS_2_2",
    "SEED_SALT%": "0"
  },
  "targets": [
    {
      "target_name": "decryptor",
      "sources": ["src/decryptor.cc"],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS",
        "NAPI_VERSION=3",
        "GAME_VERSION=\"<(GAME_VERSION)\"",
        "RELEASE_DATE=\"<(RELEASE_DATE)\"",
        "SEED_A=\"<(SEED_A)\"",
        "SEED_B=\"<(SEED_B)\"",
        "SEED_C=\"<(SEED_C)\"",
        "SEED_D=\"<(SEED_D)\"",
        "SEED_SALT=<(SEED_SALT)"
      ]
    }
  ]
}
