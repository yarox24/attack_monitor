from multiprocessing import Process
from abc import ABCMeta, abstractmethod
import time

class Feeder(Process):
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

    def set_ultra_mq(self, ultra_mq):
        self.ultra_mq = ultra_mq

    def add_to_ultra_mq(self, mq):
        self.ultra_mq.put(mq)
        #print("Passed event")

    def set_process_tree(self, pt):
        self.PROCESS_TREE = pt

    def set_mutex(self, mutex):
        self.mutex = mutex

    def get_mutex_value(self):
        return self.mutex.value

    def global_break(self):
        time.sleep(0.001)

    def set_config_options(self, options):
        self.options = options

    def get_config_option(self, option_name):
        try:
            return self.options[option_name]
        except Exception:
            return None

