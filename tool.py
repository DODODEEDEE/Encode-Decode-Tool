import base64
import urllib.parse
import hashlib
import zlib

# ENCODING FUNCTIONS
def encode_base64(text):
    return base64.b64encode(text.encode()).decode()

def encode_base32(text):
    return base64.b32encode(text.encode()).decode()

def encode_url(text):
    return urllib.parse.quote(text)

def encode_sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()

def encode_sha512(text):
    return hashlib.sha512(text.encode()).hexdigest()

def encode_md5(text):
    return hashlib.md5(text.encode()).hexdigest()

def encode_hex(text):
    return text.encode().hex()

def encode_binary(text):
    return ' '.join(format(ord(char), '08b') for char in text)

def encode_reverse(text):
    return text[::-1]

def encode_rot13(text):
    return text.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 
                                       "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))

def encode_bcrypt(text):
    return hashlib.pbkdf2_hmac('sha256', text.encode(), b'salt', 100000).hex()

def encode_xor(text, key=42):
    return ''.join(chr(ord(c) ^ key) for c in text)

def encode_ascii85(text):
    return base64.a85encode(text.encode()).decode()

def encode_html_entity(text):
    return ''.join(f'&#{ord(c)};' for c in text)

def encode_zlib(text):
    return base64.b64encode(zlib.compress(text.encode())).decode()

# ---- DECODING FUNCTIONS ----
def decode_base64(text):
    try:
        return base64.b64decode(text).decode()
    except Exception:
        return "Invalid Base64"

def decode_base32(text):
    try:
        return base64.b32decode(text).decode()
    except Exception:
        return "Invalid Base32"

def decode_url(text):
    return urllib.parse.unquote(text)

def decode_hex(text):
    try:
        return bytes.fromhex(text).decode()
    except ValueError:
        return "Invalid Hexadecimal"

def decode_binary(text):
    try:
        return ''.join(chr(int(char, 2)) for char in text.split())
    except ValueError:
        return "Invalid Binary"

def decode_reverse(text):
    return text[::-1]

def decode_rot13(text):
    return text.translate(str.maketrans("NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm", 
                                       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"))

def decode_xor(text, key=42):
    return ''.join(chr(ord(c) ^ key) for c in text)

def decode_ascii85(text):
    try:
        return base64.a85decode(text.encode()).decode()
    except Exception:
        return "Invalid ASCII85"

def decode_html_entity(text):
    return ''.join(chr(int(code[2:])) for code in text.split("&#")[1:])

def decode_zlib(text):
    try:
        return zlib.decompress(base64.b64decode(text)).decode()
    except Exception:
        return "Invalid Zlib"

# TOOL FUNCTION
def tool_encode_decode(action, text, key=42):
    if action == "encode":
        return {
            "Base64": encode_base64(text),
            "Base32": encode_base32(text),
            "URL": encode_url(text),
            "SHA256": encode_sha256(text),
            "SHA512": encode_sha512(text),
            "MD5": encode_md5(text),
            "Hexadecimal": encode_hex(text),
            "Binary": encode_binary(text),
            "Reverse": encode_reverse(text),
            "ROT13": encode_rot13(text),
            "Bcrypt": encode_bcrypt(text),
            "XOR": encode_xor(text, key),
            "ASCII85": encode_ascii85(text),
            "HTML Entity": encode_html_entity(text),
            "Zlib": encode_zlib(text),
        }
    elif action == "decode":
        return {
            "Base64": decode_base64(text),
            "Base32": decode_base32(text),
            "URL": decode_url(text),
            "Hexadecimal": decode_hex(text),
            "Binary": decode_binary(text),
            "Reverse": decode_reverse(text),
            "ROT13": decode_rot13(text),
            "XOR": decode_xor(text, key),
            "ASCII85": decode_ascii85(text),
            "HTML Entity": decode_html_entity(text),
            "Zlib": decode_zlib(text),
        }
    else:
        return {"Error": "Invalid action. Please choose '1' for decode or '2' for encode."}

# ---- MAIN ----
if __name__ == "__main__":
    print("Select action:")
    print("  Decode :1")
    print("  Encode :2")
    
    choice = input("Input 1 or 2: ").strip()
    if choice == "1":
        action = "decode"
    elif choice == "2":
        action = "encode"
    else:
        print("Invalid choice. Only '1' or '2' is allowed.")
        exit()

    input_text = input("Enter text: ")
    
    # Ask for XOR key input
    try:
        key = int(input("Enter XOR key (default is 42): ").strip() or 42)  # Default to 42 if no input
    except ValueError:
        print("Invalid XOR key. Using default key (42).")
        key = 42
    
    results = tool_encode_decode(action, input_text, key)

    print("\n=== Results ===")
    for method, result in results.items():
        print(f"{method}: {result}\n\n")
