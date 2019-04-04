from abc import ABCMeta, abstractmethod

class Parser():
    __metaclass__ = ABCMeta

    def getName(self):
        return self.__class__.__name__.lower()

    '''def getConfigName(self):
        return self.configname.lower()'''

    '''def disable(self):
        self.enabled = False'''

    '''def isEnabled(self):
        return self.enabled'''

    '''def setAdditionalInfo(self, additional_info):
        self.additional_info = additional_info'''

    @abstractmethod
    def create_alert(self, pass_mq):
        raise NotImplemented

    def get_capabilities(self):
        return self.capabilities

    @abstractmethod
    def add_to_malware_report(self, pass_mq):
        raise NotImplemented

    @abstractmethod
    def init(self, CONTAINERS=None):
        self.CONTAINERS = CONTAINERS
