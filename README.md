# Encoding-Decoding-Tool
Encoding and Decoding Toolkit

A simple Python-based toolkit for encoding and decoding text in multiple formats. This tool supports common encoding methods like Base64, URL, and Hex, as well as hashing algorithms like SHA256, MD5, and more.

---

 Features

- Encoding:
  - Base64, Base32, URL, Hexadecimal, Binary
  - Hashing: SHA256, SHA512, MD5, Bcrypt
  - ROT13, Reverse text, ASCII85, HTML Entity
  - Zlib compression with Base64 encoding
  - XOR encoding with a customizable key
  
- Decoding:
  - Base64, Base32, URL, Hexadecimal, Binary
  - Reverse text, ROT13, ASCII85
  - HTML Entity decoding
  - Zlib decompression

---

 Installation

Clone the repository:
   ```bash
   git clone https://github.com/DODODEEDEE/Encode-Decode-Tool
   cd Encoding-Decoding-Tool
   ```
Run the script using Python:
   ```bash
   python3 tool.py
   ```

---

 Usage

1. Choose an action:
   - Enter `1` to decode text.
   - Enter `2` to encode text.
   
2. Enter the text you want to encode or decode.

3. For XOR encoding/decoding:The tool will ask for an XOR key.If you want to use the default key (42), press Enter.Otherwise, enter a custom key (integer) to use for XOR operations.

4. The tool will display results in all supported formats.
