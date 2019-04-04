from abc import ABCMeta, abstractmethod
import mmap

class EvtxProvider:
    __metaclass__ = ABCMeta
    path = None
    recovery = None
    handle = None
    error = None
    valid = None
    signature_valid = None
    map = None

    def __init__(self, path, recovery=True):
        self.path = path
        self.recovery = recovery
        self.valid = False
        self.signature_valid = False

        try:
            self.handle = open(path, 'rb')

            #SIGNATURE CHECK
            if self.handle.read(8) == b'ElfFile\x00':
                self.handle.seek(0)
                self.signature_valid = True
                self.valid = True

        except IOError as ioe:
            self.error = ioe.strerror

    def mmap_file(self):
        try:
            #MMAP - Windows
            self.map = mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_READ)
        except IOError as e:
            self.error =  str(e.strerror)
            self.valid = False

    @abstractmethod
    def iterate_over_records(self):
        raise NotImplementedError

    def get_error(self):
        return self.error

    def is_valid(self):
        return self.valid

    def is_signature_valid(self):
        return self.signature_valid

    @abstractmethod
    def iterate_over_xml(self):
        raise NotImplementedError

    @abstractmethod
    def iterate_over_records(self):
        raise NotImplementedError

    @abstractmethod
    def iterate_over_events(self):
        raise NotImplementedError