import os
from sqlalchemy import Column, DateTime, String, Integer, ForeignKey, func, select, MetaData, func
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Logger:
    def __init__(self):
        file_db = 'sdrlog.sqlite'
        from sqlalchemy import create_engine
        self.engine = create_engine('sqlite:///' + file_db)
        from sqlalchemy.orm import sessionmaker
        self.session = sessionmaker()
        self.session.configure(bind=self.engine)
        if not os.path.exists(file_db):
            Base.metadata.create_all(self.engine)
            self.initDb()

    def getTables(self):
        tableDict = {}
        for n, _t in enumerate(Base.metadata.tables):
            tableDict.update({n + 1: _t})
        return tableDict

    def getTableFields(self, tName):
        return Base.metadata.tables[tName].columns.keys()

    def getAllTableData(self, tName):
        meta = MetaData(self.engine, reflect=True)
        conn = self.engine.connect()
        table = meta.tables[tName]
        res = conn.execute(select([table]))
        return res

    def setData(self, tName, tData):
        meta = MetaData(self.engine, reflect=True)
        conn = self.engine.connect()
        table = meta.tables[tName]
        ins = table.insert().values(tData)
        conn.execute(ins)

    def initDb(self):
        session = self.session()
        session.add(TestStatus(name='Pass'))
        session.add(TestStatus(name='Fail'))
        session.add(TestType(name='MTDI DOHA'))
        session.add(TestType(name='MSDH External clock'))
        session.add(TestType(name='MSDH install patch'))
        session.commit()


class TestType(Base):
    __tablename__ = 'test_type'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)


class TestStatus(Base):
    __tablename__ = 'test_status'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)


class TestLog(Base):
    __tablename__ = 'test_log'
    id = Column(Integer, primary_key=True)
    date = Column(DateTime, default=func.now(), nullable=False)
    device = Column(String)
    sn = Column(String)
    mac = Column(String)
    ip = Column(String)
    testtype_id = Column(Integer, ForeignKey('test_type.id'))
    testtype = relationship(TestType, backref=backref('test_type', uselist=True))
    teststatus_id = Column(Integer, ForeignKey('test_status.id'))
    teststatus = relationship(TestStatus, backref=backref('test_status', uselist=True))
