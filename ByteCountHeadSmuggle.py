import sys

def count_bytes_and_convert(filename):
    with open(filename, 'r') as f:
        text = f.read()
    
    byte_length = len(text.encode('utf-8'))
    hex_value = hex(byte_length)[2:]
    
    print(f"Byte length: {byte_length}")
    print(f"Hex value: {hex_value}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py input.txt")
        sys.exit(1)
    count_bytes_and_convert(sys.argv[1])
