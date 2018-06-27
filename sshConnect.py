import paramiko


class SshConnect:
    def __init__(self, host) -> None:
        super().__init__()
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.host = host
        self.user = 'root'
        self.secret = 'AxellAdmin4050'
        self.port = 22
        return self.connect(self.host, self.user, self.secret, self.port)

    def connect(self, host, user, secret, port):
        try:
            return self.client.connect(hostname=host, username=user, password=secret, port=port, timeout=60)
        except Exception as e:
            print('Error: ', str(e))
            input("Press enter to continue")

    def sendCommand(self, command):
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=3)
            return stdout.read() + stderr.read()
        except Exception as e:
            print("Run command error: {}".format(str(e)))
            return None

    def getIdProcByName(self, name):
        data = self.sendCommand('ps')
        answer = data.decode("utf-8").split('\n')
        for i in answer:
            if name not in i:
                continue
            else:
                return self.pIdProc.search(i).group(0)
        return None

    def getDeviceName(self):
        listDir = list(self.sendCommand('ls /mnt/axell/etc/target').decode('utf-8').split('\n'))
        for i in listDir:
            if i not in ('current', ''):
                return i
        return None

    def getDeviceMac(self):
        ifaces = self.sendCommand("/sbin/ifconfig -a |awk '/^[a-z]/ { iface=$1; mac=$NF; next }/inet addr:/ { print iface, mac }'").decode('utf-8').split('\n')
        for i in ifaces:
            if 'eth0' in i.lower():
                return self.pMacAddress.search(i).group(0)
        return None