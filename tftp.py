
# -*- coding: utf-8 -*-

"""
Time:     2022.01.17
Author:   Athrunsunny
Version:  V 0.1
File:     tftpClient.py
Describe:
"""
from socket import *
import struct


class TFTPClient:
    _DOWNLOAD = 1
    _UPLOAD = 2
    _DATA = 3
    _ACK = 4
    _ERROR = 5

    def __init__(self, ip, port=69):
        self.udpSocket = socket(AF_INET, SOCK_DGRAM)
        self.serverAddr = (ip, port)

    def download(self, fileName):
        self.udpSocket = socket(AF_INET, SOCK_DGRAM)
        fileName = fileName.encode()
        # 发送下载请求
        req = struct.pack(str("!H%dsb5sb" % len(fileName)), self._DOWNLOAD, fileName, 0, b"octet", 0)
        self.udpSocket.sendto(req, self.serverAddr)
        print("client download file ：%s" % fileName)

        recvFrameNum = 1
        try:
            while True:
                # 接收数据
                recvData, recvAddr = self.udpSocket.recvfrom(1024)
                cmdType, frameNum = struct.unpack("!HH", recvData[:4])
                if cmdType == self._DATA and frameNum == recvFrameNum:
                    # 打开文件
                    if frameNum == 1:
                        fileRecv = open(fileName, "ab")
                    fileRecv.write(recvData[4:])

                    ack = struct.pack("!HH", self._ACK, frameNum)
                    self.udpSocket.sendto(ack, recvAddr)
                    if len(recvData) < 516:
                        fileRecv.close()
                        fileRecv = None
                        print("receive done")
                        break
                    recvFrameNum += 1
                elif cmdType == self._ERROR:
                    print("server error")
                    break
        finally:
            if fileRecv is not None:
                fileRecv.close()

    def upload(self, fileName):
        # 若此处不新建套接字，当重复使用时会出现异常
        self.udpSocket = socket(AF_INET, SOCK_DGRAM)
        fileName = fileName.encode()
        # 发送上传请求
        req = struct.pack(str("!H%dsb5sb" % len(fileName)), self._UPLOAD, fileName, 0, b"octet", 0)
        self.udpSocket.sendto(req, self.serverAddr)

        recvData, recvAddr = self.udpSocket.recvfrom(1024)
        cmdType, frameNum = struct.unpack("!HH", recvData[:4])
        if cmdType != self._ACK or frameNum != 0:
            return False
        try:
            print("client upload file ：%s" % fileName)
            try:
                fileUpload = open(fileName, "rb")
            except:
                print("file %s does not exit" % fileName)
                # 向 client 发送异常信息
                errInfo = struct.pack("!HHHb", 5, 5, 5, 0)
                self.udpSocket.sendto(errInfo, recvAddr)
                return False
            frameNum = 1

            while True:
                fileData = fileUpload.read(512)
                # 打包
                frameData = struct.pack(str("!HH"), 3, frameNum) + fileData
                # 发送
                for i in range(0, 3):
                    self.udpSocket.sendto(frameData, recvAddr)
                    if len(fileData) < 512:
                        print("file send done")
                        fileUpload.close()
                        fileUpload = None
                        return True
                    # 等待 server 响应
                    recvData, recvAddr = self.udpSocket.recvfrom(1024)
                    cmdType, recvFrameNum = struct.unpack("!HH", recvData[:4])
                    if cmdType == self._ACK and recvFrameNum == frameNum:
                        break
                    elif i == 3:
                        print("link error")
                        # 向 client 发送异常信息
                        errInfo = struct.pack("!HHHb", 5, 5, 5, 0)
                        self.udpSocket.sendto(errInfo, recvAddr)
                        exit()
                frameNum += 1
        finally:
            if fileUpload is not None:
                fileUpload.close()


if __name__ == "__main__":
    client = TFTPClient(ip='192.168.137.187') # 服务端的ip地址
    client.upload('test.txt')
