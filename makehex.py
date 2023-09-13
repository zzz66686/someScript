import binascii

with open('rawdata.bin', 'r') as f:
    content = f.read()

writeData = binascii.a2b_hex(content)

with open('rawdata.txt', 'wb') as f:
    f.write(writeData)
