import frida
import sys

addr = '127.0.0.1'
fridaDevice = frida.get_device_manager().add_remote_device(addr)
#fridaDevice = frida.get_usb_device()
print(fridaDevice)

#allProcess = fridaDevice.enumerate_processes()
#print(allProcess)

with open('./test.js', 'r') as f:
    jscode = f.read()


def printMessage(message,data):
    if message['type'] == 'send':
        print('[*] {0}'.format(message['payload']))
        if message['payload'] == 'protoData':
            #print(data)
            dataLen = len(data)
            with open(str(dataLen), 'wb') as f:
                f.write(data)

    else:
        print(message)

fridaSession = fridaDevice.attach('CellNetworkManager') 
#fridaSession = fridaDevice.attach(11671) 

print(fridaSession)

script = fridaSession.create_script(jscode)
script.on('message',printMessage)
script.load()
sys.stdin.read()
