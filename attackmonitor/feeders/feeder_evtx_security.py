from .feeder import *
from stone_engine import evtx_subscriber
from feeders.structures import *
from utils.nicedate import NiceDate

class feeder_evtx_security(Feeder):

    def getName(self):
        return 'evtx_security'

    def run(self):
        for er in evtx_subscriber.subscribe_and_yield_events('Security'):
            pass_mq = mq(er, TYPE_LOG_EVENT, self.getName(), NiceDate.log_event_to_nice_date(er), generate_mq_key(er, self.getName()), None)

            self.add_to_ultra_mq(pass_mq)
            self.global_break()
