# glyph-cipher

`glyph-cipher` is an offline, two-way CLI credential translator. It keeps
credentials and the master passphrase in memory only; encrypted output is
represented by a custom Unicode glyph alphabet.

## Cryptographic design

- A fresh 16-byte random salt derives a 32-byte AES key with PBKDF2-HMAC-SHA256
  using 600,000 iterations.
- A fresh 12-byte random nonce is used with AES-256-GCM, providing
  confidentiality and tamper authentication.
- The output payload is `salt + nonce + ciphertext_and_tag`, encoded as
  unpadded URL-safe Base64 and mapped one-to-one to 64 custom glyphs.
- Decryption rejects invalid symbols, altered ciphertext, wrong passphrases, and
  invalid UTF-8 with `GlyphCipherError`.

No credential data is written to disk. Clipboard content is cleared after 15
seconds when it still contains a decrypted credential.

## Linux setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo apt install xclip
python main.py
```

`wl-clipboard` can be used instead of `xclip` on Wayland systems. If no
clipboard provider is installed, the CLI warns without crashing.

## Customizing the alphabet

Edit `GLYPH_ALPHABET` in `cipher.py` to provide exactly 64 unique, non-whitespace
symbols. The list order is part of the encoding format: changing it makes
existing glyph strings undecodable, so retain the original list when data must
remain compatible. Import-time assertions verify the required constraints.
