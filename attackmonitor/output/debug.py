from output.logger_base import LoggerBase
from feeders.structures import *
from output.dynamic import *
from utils.configer import *

class LoggerDebug(LoggerBase):

    def extra_init(self):
        self.WRITE_FILES = dict()

        cc = Config()
        self.DEBUG_LOGS_DIR = cc.get_debug_log_directory()

    def save_to_file(self, line, date_day):
        f = None

        if date_day in self.WRITE_FILES:
            f = self.WRITE_FILES[date_day]
        else:
            self.WRITE_FILES[date_day] = open("{}{}.txt".format(self.DEBUG_LOGS_DIR, date_day), 'a', encoding='utf-8')
            f = self.WRITE_FILES[date_day]

        if f is None:
            raise AssertionError
        f.write(line + "\n")
        f.flush()

    def write_alert(self, var):
        supported = var.supported
        mqvar = var.mq

        dwt = mqvar.datetime_with_timezone
        date_day = determine_log_file_name_from_var(mqvar)

        if isinstance(mqvar, mq):
            line = mq_to_oneline(mqvar)
            line = no_newlines(line)
            self.save_to_file(line, date_day)
        else:
            raise AssertionError

    def run(self):
        while True:
            var = self.get_from_input_queue()
            self.write_alert(var)











'''def __new__(cls):
    if not hasattr(cls, 'instance'):
        cls.instance = super(DebugLogging, cls).__new__(cls)
    return cls.instance'''