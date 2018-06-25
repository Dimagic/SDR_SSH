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
