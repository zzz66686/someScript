# -*- coding: utf-8 -*-

"""
Time:     2022.01.17
Author:   Athrunsunny
Version:  V 0.1
File:     tftpServer.py
Describe:
"""
from socket import *
import struct


class TFTPServer:
    _DOWNLOAD = 1
    _UPLOAD = 2
    _DATA = 3
    _ACK = 4
    _ERROR = 5

    def __init__(self):
        self.serverSocket = socket(AF_INET, SOCK_DGRAM)
        self.serverSocket.bind(("", 69))

    def run(self):
        while True:
            print("Wait for client")
            self.listen()

            if self.cmdType == self._DOWNLOAD:
                self.download()
            elif self.cmdType == self._UPLOAD:
                self.upload()

    def listen(self):
        # 等待client链接
        self.recvData, self.recvAddr = self.serverSocket.recvfrom(1024)
        self.cmdType = struct.unpack("!H", self.recvData[:2])[0]

    # 客户端请求下载
    def download(self):
        # 新建随机端口
        udpSocket = socket(AF_INET, SOCK_DGRAM)
        fileReq = None
        try:
            fileReqName = self.recvData[2:-7].decode()
            print("client download file ：%s" % fileReqName)
            try:
                fileReq = open(fileReqName, "rb")
            except:
                print("file %s does not exit" % fileReqName)
                errInfo = struct.pack("!HHHb", 5, 5, 5, 0)
                udpSocket.sendto(errInfo, self.recvAddr)
                return False
            frameNum = 1

            while True:
                fileData = fileReq.read(512)
                # 打包
                frameData = struct.pack(str("!HH"), 3, frameNum) + fileData
                # 发送
                for i in range(0, 3):
                    udpSocket.sendto(frameData, self.recvAddr)
                    if len(fileData) < 512:
                        print("file send done")
                        fileReq.close()
                        fileReq = None
                        return True

                    # 等待client响应
                    self.recvData, self.recvAddr = udpSocket.recvfrom(1024)
                    cmdType, recvFrameNum = struct.unpack("!HH", self.recvData[:4])
                    if cmdType == self._ACK and recvFrameNum == frameNum:
                        break
                    elif i == 3:
                        print("link error")
                        errInfo = struct.pack("!HHHb", 5, 5, 5, 0)
                        udpSocket.sendto(errInfo, self.recvAddr)
                        exit()
                frameNum += 1
        finally:
            if fileReq is not None:
                fileReq.close()

    # 客户端请求上传
    def upload(self):
        # 新建随机端口
        udpSocket = socket(AF_INET, SOCK_DGRAM)
        ack = struct.pack("!HH", self._ACK, 0)
        udpSocket.sendto(ack, self.recvAddr)
        fileReqName = self.recvData[2:-7].decode()
        recvFrameNum = 1
        while True:
            recvData, recvAddr = udpSocket.recvfrom(1024)
            # 数据帧
            cmdType, frameNum = struct.unpack("!HH", recvData[:4])
            if cmdType == self._DATA and frameNum == recvFrameNum:
                # 打开文件
                if frameNum == 1:
                    fileRecv = open(fileReqName, "ab")
                fileRecv.write(recvData[4:])

                # 响应
                ack = struct.pack("!HH", self._ACK, frameNum)
                udpSocket.sendto(ack, recvAddr)
                if len(recvData) < 516:
                    fileRecv.close()
                    fileRecv = None
                    print("done")
                    break
                recvFrameNum += 1
            elif cmdType == self._ERROR:
                print("client link error")
                break


if __name__ == "__main__":
    server = TFTPServer()
    server.run()

