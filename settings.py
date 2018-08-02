import os
from prettytable import PrettyTable
from logger import Logger


class Settings:
    def __init__(self, parent):
        self.parent = parent
        os.system("cls")
        print("***********************")
        print("******* SDR SSH *******")
        print("***********************")
        try:
            self.tables = Logger().getTables()
            for n, i in enumerate(self.tables.values()):
                print("{}: {}".format(n + 1, i))
        except Exception as e:
            input(str(e))
        print("0: Exit")
        try:
            n = int(input("Choose table: "))
            if n == 0:
                parent.menu()
            if n not in self.tables.keys():
                self.__init__()
            else:
                self.tableMenu(n)
        except Exception as e:
            print(str(e))
            # self.__init__(parent=parent)

    def tableMenu(self, n_table):
        os.system("cls")
        print("Current table: {}".format(self.tables.get(n_table)))
        print("1: Table view")
        print("0: Return")
        try:
            n = int(input("Choose operation: "))
        except:
            self.tableMenu(n_table)
        if n == 1:
            self.tableView(n_table)
        elif n == 0:
            self.__init__(parent=self.parent)
        else:
            self.tableMenu(n_table)

    def tableView(self, n_table):
        logger = Logger()
        tableName = self.tables.get(n_table)
        columns = logger.getTableFields(tableName)
        pTable = PrettyTable(columns)
        for row in logger.getAllTableData(tableName):
            pTable.add_row(row)
        print(pTable)
        input("Press any key for return")
        self.tableMenu(n_table=n_table)




