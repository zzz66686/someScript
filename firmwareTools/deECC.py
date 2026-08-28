fr = open('MX30LF1GE8AB.bin', 'rb')
fw = open('deECCMX30LF1GE8AB.bin', 'wb')

'''
content = fr.read(0x840)
with open('page1', 'wb') as f:
    f.write(content)

content = fr.read(0x840)
content = fr.read(0x840)
content = fr.read(0x840)
content = fr.read(0x840)
content = fr.read(0x840)
content = fr.read(0x840)
with open('page6', 'wb') as f:
    f.write(content)


'''
while 1:
    content = fr.read(0x800)
    if len(content) == 0:
        break
    fw.write(content)    
    fr.read(0x40)    
    

fr.close()
fw.close()
