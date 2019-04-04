from abc import ABCMeta, abstractmethod
from multiprocessing import Process

import time

class LoggerBase(Process):
    __metaclass__ = ABCMeta

    def __init__(self):
        super(LoggerBase, self).__init__()
        self.daemon = True
        self.extra_init()

    @abstractmethod
    def extra_init(self):
        raise NotImplemented

    @abstractmethod
    def getName(self):
        raise NotImplemented

    @abstractmethod
    def run(self):
        raise NotImplemented

    def set_input_queqe(self, INPUT_QUEUE):
        self.INPUT_QUEUE = INPUT_QUEUE

    def get_from_input_queue(self):
        return self.INPUT_QUEUE.get()