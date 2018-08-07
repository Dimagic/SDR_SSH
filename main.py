import _cffi_backend
import os
import paramiko
import socket
import re
import sys
from sys import stdout
import subprocess
import ipaddress
import time
from datetime import datetime
import sqlalchemy.exc
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait as wait

from config import Config
from logger import Logger
from settings import Settings

__version__ = '0.3.6'


class Main:
    pIdProc = re.compile(r"^[0-9\s]+")
    pUptimeFull = re.compile(r"^[0-9a-z:\s]+")
    pUptime = re.compile(r"\s((\d){1,2})\s")
    # pNameProc = re.compile(r":\d\d\s(.+)$")
    pIpAddress = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    pNetwork = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.)")
    pMacAddress = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")

    def __init__(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        wk_dir = os.path.dirname(os.path.realpath('__file__'))
        self.logFile = wk_dir + '\systemlog.log'
        self.scriptNameAuth = 'authAxell.exe'
        self.scriptNameUpload = 'fileUpload.exe'
        self.authScript = wk_dir + '\\autoit\\' + self.scriptNameAuth
        self.fileUploadScript = wk_dir + '\\autoit\\' + self.scriptNameUpload
        self.config = None
        self.host = None
        self.info = None
        self.name = None
        self.sn = None
        self.user = None
        self.secret = None
        self.port = None
        self.statusTest = None
        self.testResult = {}
        self.menu()

    def menu(self):
        self.testResult = {}
        self.sn = None
        self.name = None
        self.statusTest = 'Pass'
        os.system("cls")
        print(__version__)
        # print('Current system: {}'.format(platform.platform()))
        print("***********************")
        print("******* SDR SSH *******")
        print("***********************")
        print("1: MTDI DOHA")
        print("2: MSDH External clock")
        print("3: MSDH install patch")
        print("9: Settings")
        # print("9: Open log file")
        print("0: Exit")
        print("***********************")
        print("Self IP address: {}".format(self.getSelfIp()))
        try:
            menu = int(input("Choose operation: "))
        except Exception:
            self.menu()
        if menu == 1:
            self.runMtdiDoha()
        elif menu == 2:
            self.runMsdhEC()
        elif menu == 3:
            self.installMsdhPatchIE()
        elif menu == 9:
            Settings(self)
        # elif menu == 9:
        #     try:
        #         os.startfile(self.logFile)
        #     except Exception as e:
        #         print(str(e))
        #         input("Press enter to continue")
        #     finally:
        #         self.menu()
        elif menu == 0:
            sys.exit(0)
        else:
            self.menu()

    def sshConnect(self, user, secret, port):
        self.host = self.getAvalIp()
        if self.host is None:
            stdout.write("\n")
            stdout.flush()
            print("Host not found or incorrect")
            input("Press enter to continue")
            self.menu()
        self.config = Config(self)
        try:
            self.client.connect(hostname=self.host, username=user,
                                password=secret, port=port, timeout=60)
            self.sn = re.search(r"(\w{4}$)", self.sendCommand('cat /etc/HOSTNAME').decode("utf-8")).group(0)
            self.name = self.getDeviceName()
            self.testResult.update({'sn': self.sn})
            self.testResult.update({'device': self.name})
            if None in (self.sn, self.name):
                input("Device name or SN not found. Press enter to continue")
                self.menu()
            print("Connected to device {} SN: {}".format(self.name, self.sn))
        except Exception as e:
            print('Error: ', str(e))
            input("Press enter to continue")
            self.menu()

    def runMtdiDoha(self):
        self.sshConnect('root', 'AxellAdmin4050', 22)
        if not self.verifiDevice('MTDI'):
            input('Device {} not support. Press enter to continue'.format(self.name))
            self.client.close()
            self.menu()
        self.waitUpTime(10)
        for n in range(5):
            self.sendCommand('rm /tmp/SuperviseTheDaemons')
            stdout.write('\rRemove directory {}'.format(n))
            time.sleep(1)
        stdout.write("\n")

        self.killProc(('hw_watchdog.sh', 'xmasd -d'))
        self.waitReboot()
        self.writeLog('MTDI DOHA')
        self.client.close()
        self.testResult.update({'date': datetime.now()})
        # self.testResult.update('teststatus_id', )
        try:
            Logger().setData('test_log', self.testResult)
        except sqlalchemy.exc as e:
            print(str(e))
        input("Press enter to continue")
        self.menu()

    def runMsdhEC(self):
        self.sshConnect('root', 'AxellAdmin4050', 22)
        if not self.verifiDevice('MSDHExClock'):
            input('Device {} not support. Press enter to continue'.format(self.name))
            self.client.close()
            self.menu()

        for nameScript in ['CDCM', 'LMK']:
            filePresent = self.sendCommand('ls /usr/sbin/axell/target/{}/sys/hw_init/{}_ORIG.sh'.
                                           format(self.name, nameScript))
            if "No such file or directory" not in str(filePresent):
                print('rename {}.sh to {}_ORIG.sh: SKIPED'.format(nameScript, nameScript))
                continue
            self.sendCommand('mv /usr/sbin/axell/target/{}/sys/hw_init/{}.sh '
                             '/usr/sbin/axell/target/{}/sys/hw_init/{}_ORIG.sh'
                             .format(self.name, nameScript, self.name, nameScript))
            print('rename {}.sh to {}_ORIG.sh: OK'.format(nameScript, nameScript))
        udIp = self.sendCommand('/sbin/udhcpc eth0').decode('utf-8').split('\n')
        for i in udIp:
            if 'Sending select for' in i:
                if self.pIpAddress.search(i).group(0) == self.host:
                    print('udhcpc {} OK'.format(self.host))
                    break

        for nameScript in ['CDCM', 'LMK']:
            self.sendCommand('wget -O /tmp/{}.sh ftp://{}/MSDH005/{}.sh'.
                                   format(nameScript, self.getSelfIp(), nameScript))
            self.sendCommand('cp /tmp/{}.sh /usr/sbin/axell/target/{}/sys/hw_init/'.
                                   format(nameScript, self.name))
            self.sendCommand('chmod 777 /usr/sbin/axell/target/{}/sys/hw_init/{}.sh'.
                                   format(self.name, nameScript))

        str1 = '# avichay: updated better phase noise current 1065fs'
        str2 = '# avichay 25Mhz osc seperate CPRI Ethernet : orig 0x20BC lvcmos but should be lvds'
        if str1 and str2 in self.sendCommand('cat /usr/sbin/axell/target/{}/sys/hw_init/'
                                             'CDCM.sh'.format(self.name)).decode('utf-8'):
            print('Script CDCM.sh: OK')
        else:
            print('Script CDCM.sh: FAIL')
            self.statusTest = 'Fail'

        str1 = 'avichay- 24.576Mhz Master clk with 1536K PFD'
        if str1 in self.sendCommand('cat /usr/sbin/axell/target/{}/sys/hw_init/'
                                    'LMK.sh'.format(self.name)).decode('utf-8'):
            print('Script LMK.sh: OK')
        else:
            print('Script LMK.sh: FAIL')
            self.statusTest = 'Fail'

        self.sendCommand('/sbin/reboot')
        self.waitReboot()
        self.client.close()
        self.writeLog('MSDH Clock')
        input("Press enter to continue...")
        self.menu()

    # def installMsdhPatch(self):
    #     return
    #     self.sshConnect('root', 'AxellAdmin4050', 22)
    #     patchName = Config(self).getConfAttr('patches', self.name)
    #     self.sendCommand('wget -O /tmp/{} ftp://{}/MSDH005/{}'.format(patchName, self.getSelfIp(), patchName))
    #     self.sendCommand('rm /tmp/SuperviseTheDaemons')
    #     self.sendCommand('/tmp/pre-install.sh')
    #     self.sendCommand('cd /tmp; tar -xf ../tmp/{}'.format(patchName))
    #     self.sendCommand('/tmp/post-install.sh')
    #     self.waitReboot()
    #     self.client.close()
    #     self.writeLog('Patch')
    #     input("Press enter to continue...")
    #     self.menu()

    def installMsdhPatchIE(self):
        self.sshConnect('root', 'AxellAdmin4050', 22)
        driver = webdriver.Ie(executable_path=r"IEDriverServer.exe")
        driver.get('http://{}'.format(self.host))
        # wait(driver, 5).until(EC.alert_is_present())
        wait(driver, 5)
        os.startfile(self.authScript)
        while self.scriptNameAuth in subprocess.Popen('tasklist', stdout=subprocess.PIPE).communicate()[0].decode("utf-8"):
            time.sleep(1)
        n = 1
        while ('initial_setup' not in driver.current_url) and ('target' not in driver.current_url):
            time.sleep(1)
            n += 1
            stdout.write('\rWaiting start page: {}'.format(n))
            stdout.flush()
        if 'initial_setup' in driver.current_url:
            driver.find_element_by_id('num_of_operator').send_keys('1')
            driver.find_element_by_id('op_name_1').send_keys('oper1')
            driver.find_element_by_id('apply-btn').click()
            wait(driver, 5)
        driver.get('http://{}/upgrade/'.format(self.host))
        wait(driver, 5)
        subprocess.Popen(self.fileUploadScript)
        while self.scriptNameUpload in subprocess.Popen('tasklist', stdout=subprocess.PIPE).communicate()[0].decode("utf-8"):
            time.sleep(1)
        self.waitReboot()
        os.system("taskkill /f /im IEDriverServer.exe")
        self.menu()

    def killProc(self, nameProcList):
        idDict = {}
        for proc in nameProcList:
            idDict.update({proc: self.getIdProcByName(proc)})
        if None in idDict.values():
            for i in reversed(range(60)):
                stdout.write("\rNot found all process. Waiting {} seconds".format(i))
                stdout.flush()
                time.sleep(1)
            stdout.write("\n")
            self.killProc(nameProcList)
        for idProcess in idDict:
            self.sendCommand('kill -9 {}'.format(idDict.get(idProcess)))
            time.sleep(1)
            if self.getIdProcByName(idProcess) is not None:
                self.killProc(nameProcList)
            print('Kill process {} {}'.format(idDict.get(idProcess), idProcess))

    def sendCommand(self, command):
        stdin, stdout, stderr = self.client.exec_command(command, timeout=5)
        # notprint = ('uptime')
        # if command not in notprint:
        #     print('--> {}'.format(command))
        # while True:
        #     line = tmpout.readline()
        #     if not line:
        #         break
        #     print('<-- {}'.format(line))
        return stdout.read() + stderr.read()

    def getIdProcByName(self, name):
        data = self.sendCommand('ps')
        answer = data.decode("utf-8").split('\n')
        for i in answer:
            if name not in i:
                continue
            else:
                return self.pIdProc.search(i).group(0)

    def waitUpTime(self, needTime):
        print("Waiting uptime > {} minutes".format(needTime))
        while True:
            answer = self.sendCommand('uptime').decode('utf-8')
            answer = self.pUptimeFull.search(answer).group(0)
            stdout.write("\r{}".format(answer))
            stdout.flush()
            if int(self.pUptime.search(answer).group(0)) > needTime:
                stdout.write("\n")
                break
            time.sleep(1)

    def getSelfIp(self):
        return [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if ip.startswith("11.")][:1][0]

    def getAvalIp(self):
        net_addr = self.pNetwork.search(self.getSelfIp()).group(0) + '0/24'
        ip_net = ipaddress.ip_network(net_addr)
        all_hosts = list(ip_net.hosts())

        # Configure subprocess to hide the console window
        self.info = subprocess.STARTUPINFO()
        self.info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        self.info.wShowWindow = subprocess.SW_HIDE

        macForSearch = input('Input mac-address or Ip and press Enter: ').upper().replace(":", "-")
        try:
            ip = self.pIpAddress.search(macForSearch).group(0)
            for i in list(ip.split('.')):
                if int(i) > 255:
                    return None
            print('IP for connection: {}'.format(ip))
            return ip
        except Exception:
            try:
                macForSearch = self.pMacAddress.search(macForSearch).group(0)
                self.testResult.update({"mac": macForSearch})
                print('MAC for connection: {}'.format(macForSearch))
            except Exception:
                self.menu()

        try:
            waitTime = 90
            print('Press Ctrl+C for start now')
            while waitTime >= 0:
                stdout.write('\rStart after {} seconds'.format(waitTime))
                time.sleep(1)
                waitTime -= 1
        except KeyboardInterrupt:
            pass

        try:
            for i in reversed(range(len(all_hosts))):
                output = subprocess.Popen(['ping', '-n', '1', '-w', '500', str(all_hosts[i])], stdout=subprocess.PIPE,
                                          startupinfo=self.info).communicate()[0]
                if "TTL=" not in output.decode('utf-8'):
                    stdout.write("\r{} is Offline  ".format(all_hosts[i]))
                    stdout.flush()
                else:
                    time.sleep(1)
                    pid = subprocess.Popen(["arp", "-a", str(all_hosts[i]), "-N", self.getSelfIp()], stdout=subprocess.PIPE)
                    s = pid.communicate()[0].decode("utf-8").split('\n')
                    for k in s:
                        if macForSearch.upper() in k.upper():
                            ip = self.pIpAddress.search(k).groups()[0]
                            self.testResult.update({"ip": ip})
                            stdout.write("\rCurrent host is {}".format(all_hosts[i]))
                            stdout.write("\n")
                            stdout.flush()
                            return ip
                    stdout.write("\r{} is Online  ".format(all_hosts[i]))
                    stdout.write("\n")
                    stdout.flush()
        except KeyboardInterrupt:
            self.menu()

    def waitReboot(self):
        w = 0
        while "TTL=" in subprocess.Popen(['ping', '-n', '1', '-w', '500', self.host],
                                         stdout=subprocess.PIPE,
                                         startupinfo=self.info).communicate()[0].decode('utf-8'):
            try:
                answer = self.sendCommand('uptime').decode('utf-8')
                answer = self.pUptimeFull.search(answer).group(0)
                stdout.write("\r{}".format(answer))
                time.sleep(1)
            except Exception:
                if w == 0:
                    stdout.write('\n')
                    stdout.flush()
                w += 1
                stdout.write("\rDevice will reboot now: {} seconds".format(w))
                stdout.flush()
                time.sleep(1)
        stdout.write('\n')
        w = 0
        while "TTL=" not in subprocess.Popen(['ping', '-n', '1', '-w', '500', self.host],
                                         stdout=subprocess.PIPE,
                                         startupinfo=self.info).communicate()[0].decode('utf-8'):
            w += 1
            stdout.write("\rWaiting boot {} seconds".format(w))
            time.sleep(1)
        stdout.write('\n')
        print("Boot complete")

    def writeLog(self, var):
        timeNow = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if os.path.isfile(self.logFile):
            mode = 'a'
        else:
            mode = 'w'
        with open(self.logFile, mode) as f:
            f.write("\n{} Device: {} SN: {} IP: {} Status: {} {} ".
                    format(timeNow, self.name, self.sn, self.host, var, self.statusTest))
        print("Writing log file complete")

    def getDeviceName(self):
        listDir = list(self.sendCommand('ls /mnt/axell/etc/target').decode('utf-8').split('\n'))
        for i in listDir:
            if i not in ('current', ''):
                return i

    def verifiDevice(self, var):
        cfg = list(self.config.getConfAttr('devices', var).split(';'))
        if self.name in cfg:
            return True
        return False

    def getDeviceMac(self):
        cmd = "/sbin/ifconfig -a |awk '/^[a-z]/ { iface=$1; mac=$NF; next }/inet addr:/ { print iface, mac }'"
        ifaces = self.sendCommand(cmd).decode('utf-8').split('\n')
        for i in ifaces:
            if 'eth0' in i.lower():
                return self.pMacAddress.search(i).group(0)


if __name__ == '__main__':
    prog = Main()
    sys.exit(0)
