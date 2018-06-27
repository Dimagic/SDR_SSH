import configparser


class Config:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read('./config.cfg', encoding='utf-8-sig')

    def getConfAttr(self, blockName, attrName):
        return self.config.get(blockName, attrName)


