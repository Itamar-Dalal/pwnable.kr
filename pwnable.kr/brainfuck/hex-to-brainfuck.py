def hex_to_brainfuck(hex):
    chunks = [hex[i:i+2] for i in range(0, len(hex), 2)]
    bf_code = []
    for byte in chunks:
        num = int(byte, 16)
        bf_code.append('+' * num)
    return '>'.join(bf_code)

print(hex_to_brainfuck("ff352b8bedf7e8a57ddbf7"))