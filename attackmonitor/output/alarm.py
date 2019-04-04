from output.logger_base import LoggerBase
from feeders.structures import *
from output.dynamic import *
from utils.configer import *

class LoggerAlarm(LoggerBase):

    def extra_init(self):
        self.WRITE_FILES = dict()

        cc = Config()
        self.LOGS_DIR = cc.get_log_directory()

    def save_to_file(self, line, date_day):
        f = None

        if date_day in self.WRITE_FILES:
            f = self.WRITE_FILES[date_day]
        else:
            self.WRITE_FILES[date_day] = open("{}\\{}.txt".format(self.LOGS_DIR, date_day), 'a', encoding='utf-8')
            f = self.WRITE_FILES[date_day]

        if f is None:
            raise AssertionError
        f.write(line + "\n")
        f.flush()

    def write_alert(self, al):
        save_to_date_day = determine_log_file_name_from_var(al)

        if isinstance(al, alert):
            line = alert_to_oneline(al)
            line = no_newlines(line)
            self.save_to_file(line, save_to_date_day)
        else:
            raise AssertionError

    def run(self):
        while True:
            var = self.get_from_input_queue()
            self.write_alert(var)
