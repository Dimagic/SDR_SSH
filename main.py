import _cffi_backend
import os
import paramiko
import re
import sys
from sys import stdout
import subprocess
import ipaddress
import time


class Main:
    pIdProc = re.compile(r"^[0-9\s]+")
    pUptime = re.compile(r"^[0-9a-z:\s]+")
    # pNameProc = re.compile(r":\d\d\s(.+)$")
    pIpAddress = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    pMacAddress = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")

    def __init__(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.host = None
        self.info = None
        # self.getComPort()
        # self.runParamiko()
        self.menu()

    def menu(self):
        os.system("cls")
        print("***********************")
        print("******* SDR SSH *******")
        print("***********************")
        print("1: MTDI DOHA")
        print("2: MSDH External clock")
        print("0: Exit")
        print("***********************")
        try:
            menu = int(input("Choice operation: "))
        except Exception:
            self.menu()
        if menu == 1:
            self.runMtdiDoha()
        elif menu == 2:
           self.runMsdhEC()
        elif menu == 0:
            sys.exit(0)
        else:
            self.menu()

    def sshConnect(self):
        self.user = 'root'
        self.secret = 'AxellAdmin4050'
        self.port = 22
        try:
            self.client.connect(hostname=self.host, username=self.user,
                                password=self.secret, port=self.port, timeout=60)
        except Exception as e:
            print('Error: ', str(e))
            input("Press enter to continue")
            self.menu()

    def runMtdiDoha(self):
        self.host = self.getAvalIp()
        if self.host is None:
            stdout.write("\n")
            stdout.flush()
            print("Host not found")
            input("Press enter to continue")
            self.menu()
        # self.host = '11.0.0.201'
        self.sshConnect()
        for n in range(5):
            self.sendCommand('rm /tmp/SuperviseTheDaemons')
            stdout.write('\rRemove dirrectory {}'.format(n))
            time.sleep(1)
        stdout.write("\n")

        for nameProc in ('hw_watchdog.sh', 'xmasd -d'):
            idProcess = self.getIdProcByName(nameProc)
            if not idProcess:
                print('Process {} not found'.format(nameProc))
            else:
                self.sendCommand('kill -9 {}'.format(idProcess))
                time.sleep(1)
                print('Kill process {}'.format(nameProc))
        self.waitReboot()
        self.client.close()

    def runMsdhEC(self): #00-14-B1-01-9B-DC
        self.host = self.getAvalIp()
        if self.host is None:
            stdout.write("\n")
            stdout.flush()
            print("Host not found")
            input("Press enter to continue")
            self.menu()
        self.sshConnect()
        # for nameScript in ['CDCM', 'LMK']:
        #     self.sendCommand('mv /usr/sbin/axell/target/MSDH-3.0.0.3485/sys/hw_init/{}.ch '
        #                            '/usr/sbin/axell/target/MSDH-3.0.0.3485/sys/hw_init/{}_OLD.orig'.format(nameScript))
        udIp = self.sendCommand('udhcpc eth0').decode("utf-8")
        print(udIp)

        transport = paramiko.Transport(self.host, 22)
        print(transport.connect(username=self.user, password=self.secret))
        sftp = paramiko.SFTPClient.from_transport(transport)
        print(sftp)
        sftp.close()
        input("Press enter to continue")
        self.menu()

    def sendCommand(self, command):
        stdin, stdout, stderr = self.client.exec_command(command)
        return stdout.read() + stderr.read()

    def getIdProcByName(self, name):
        data = self.sendCommand('ps')
        answer = data.decode("utf-8").split('\n')
        for i in answer:
            if name not in i:
                continue
            else:
                return self.pIdProc.search(i).group(0)

    # def getIp(self):
    #     print([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1])

    # def getComPort(self):
    #     ser = serial.Serial()
    #     listCom = list(serial.tools.list_ports.comports())
    #     print(listCom)

    def getAvalIp(self):
        net_addr = '11.0.0.0/24'
        ip_net = ipaddress.ip_network(net_addr)
        all_hosts = list(ip_net.hosts())

        # Configure subprocess to hide the console window
        self.info = subprocess.STARTUPINFO()
        self.info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        self.info.wShowWindow = subprocess.SW_HIDE

        macForSearch = input('Scan mac-address and press Enter:').upper().replace(":", "-")
        try:
            macForSearch = self.pMacAddress.search(macForSearch).group(0)
            print(macForSearch)
            # return
        except Exception:
            self.menu()
        for i in reversed(range(len(all_hosts))):
            output = subprocess.Popen(['ping', '-n', '1', '-w', '500', str(all_hosts[i])], stdout=subprocess.PIPE,
                                      startupinfo=self.info).communicate()[0]

            if "TTL=" not in output.decode('utf-8'):
                stdout.write("\r{} is Offline".format(all_hosts[i]))
                stdout.flush()
            else:
                pid = subprocess.Popen(["arp", "-a", str(all_hosts[i])], stdout=subprocess.PIPE)
                s = pid.communicate()[0].decode("utf-8").split('\n')
                for k in s:
                    if macForSearch.upper() in k.upper():
                        ip = self.pIpAddress.search(k).groups()[0]
                        stdout.write("\rCurrent host is {}".format(all_hosts[i]))
                        stdout.write("\n")
                        stdout.flush()
                        return ip
                stdout.write("\r{} is Online".format(all_hosts[i]))
                stdout.write("\n")
                stdout.flush()

    def waitReboot(self):
        while "TTL=" in subprocess.Popen(['ping', '-n', '1', '-w', '500', self.host],
                                         stdout=subprocess.PIPE,
                                         startupinfo=self.info).communicate()[0].decode('utf-8'):
                answer = self.sendCommand('uptime').decode('utf-8')
                answer = self.pUptime.search(answer).group(0)
                stdout.write("\r{}".format(answer))
                time.sleep(1)
        stdout.write('\n')
        print("System is reboot now")
        w = 0
        while "TTL=" not in subprocess.Popen(['ping', '-n', '1', '-w', '500', self.host],
                                         stdout=subprocess.PIPE,
                                         startupinfo=self.info).communicate()[0].decode('utf-8'):
            w += 1
            stdout.write("\rWaiting boot {} seconds".format(w))
            time.sleep(1)
        stdout.write('\n')
        print("Done")
        input("Press enter to continue")


if __name__ == '__main__':
    prog = Main()
    sys.exit(0)
    # 00-14-B1-01-D0-A7