

with open("udx710_module+initgc+console+sec-user-native_FDDNRSEC_21A.pac", 'rb') as f:
    c = f.read()


with open("cutFile.pac", 'wb') as f:
    f.write(c[0x830B5:0x4A8DF4])