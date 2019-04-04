import pytz
from utils import configer
from datetime import datetime
from tzlocal import get_localzone

#TIMEZONE
cc = configer.Config()
CONFIG_TIMEZONE = cc.get_config_single_category("attack_monitor.cfg", "time")['timezone']

# AUTODETECT TIMEZONE
if CONFIG_TIMEZONE == "AUTODETECT":
    CONFIG_TIMEZONE = get_localzone().zone

CONFIG_TIMEZONE_PYTZ = pytz.timezone(CONFIG_TIMEZONE)
#//TIMEZONE

class NiceDate():

    @staticmethod
    def get_now():
        return datetime.now(CONFIG_TIMEZONE_PYTZ)

    @staticmethod
    def log_event_to_nice_date(er):
        (d, milliseconds) = er.get_expanded_field_time_created_tuple()
        return d.astimezone(CONFIG_TIMEZONE_PYTZ)

    @staticmethod
    def naive_datetime_localize(d):
        return CONFIG_TIMEZONE_PYTZ.localize(d)

    @staticmethod
    def sysmon_process_string_to_nicedate(proc_string):
        d = datetime.strptime(proc_string + "000+0000", "%Y-%m-%d %H:%M:%S.%f%z")
        return d.astimezone(CONFIG_TIMEZONE_PYTZ)




