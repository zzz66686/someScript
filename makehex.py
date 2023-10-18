import binascii


with open('rawdata.txt', 'rb') as f:
    content = f.read()

writeData = binascii.a2b_hex(content)


with open('rawdata.bin', 'wb') as f:
    f.write(writeData)





with open('rawdata.bin', 'rb') as f:
    content = f.read()

writeData = binascii.b2a_hex(content)

with open('rawdata.txt', 'wb') as f:
    f.write(writeData)
