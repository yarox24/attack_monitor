from multiprocessing import Process, Manager
from abc import ABCMeta, abstractmethod
import time

class Enhancer(Process):
    __metaclass__ = ABCMeta

    def __init__(self):
        super(Process, self).__init__()
        self.daemon = True

    @abstractmethod
    def getName(self):
        raise NotImplemented

    @abstractmethod
    def run(self):
        raise NotImplemented

    def setStorage(self, storage):
        self.storage = storage

    def setLock(self, lock):
        self.lock = lock

    def releaseLock(self):
        self.lock.value = True

    def createMultiprocessingManager(self):
        self.MMinternal = Manager()

    def delay_start(self):
        time.sleep(5)

