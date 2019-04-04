from multiprocessing import Process
from .exception_engine import ExceptionEngine

class ExceptionFilter(Process):

    def __init__(self, ALERT_MQ, SHOW_MQ, EXCEPTION_RULES):
        super(Process, self).__init__()
        self.daemon = True
        self.ALERT_MQ = ALERT_MQ
        self.SHOW_MQ = SHOW_MQ
        self.EXCEPTION_RULES = EXCEPTION_RULES


    def run(self):

        ee = ExceptionEngine(self.EXCEPTION_RULES)

        while True:
            # GRAB FROM ULTRA MQ
            pass_mq = self.ALERT_MQ.get()
            #print("[{}] {} {}".format(self.name, i, pass_mq))

            if not ee.should_be_skipped(pass_mq):
                self.SHOW_MQ.put(pass_mq)
            #else:
                #print("Skipping: {}".format(pass_mq))

