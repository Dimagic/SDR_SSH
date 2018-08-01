import configparser


class Config:
    def __init__(self, parent):
        self.parent = parent
        self.config = configparser.ConfigParser()
        self.config.read('./config.cfg', encoding='utf-8-sig')

    def getConfAttr(self, blockName, attrName):
        try:
            return self.config.get(blockName, attrName)
        except Exception as e:
            print('ERROR: {}'.format(str(e)))
            input("Press enter to continue...")
            self.parent.menu()



