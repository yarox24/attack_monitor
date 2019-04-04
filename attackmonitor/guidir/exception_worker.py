from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QSystemTrayIcon
from PyQt5.QtCore import QThread, QObject, pyqtSignal, pyqtSlot
from feeders.structures import alert
from exception_package import exception_engine
import time


class QTExceptionWorker(QThread):
    show_add_exception_dialog = pyqtSignal(alert)

    def __init__(self, SHOW_MQ, TRAY_MQ, ALARM_MQ, MALWARE_MQ, EXCEPTION_RULES, parent):
        QtCore.QThread.__init__(self, parent)
        self.SHOW_MQ = SHOW_MQ
        self.TRAY_MQ = TRAY_MQ
        self.ALARM_MQ = ALARM_MQ
        self.MALWARE_MQ = MALWARE_MQ
        self.EXCEPTION_RULES = EXCEPTION_RULES
        self.parent = parent
        self.modal_dialog_active = False

        # CONNECT SIGNALS
        self.show_add_exception_dialog.connect(self.parent.show_add_exception_dialog)
        parent.unlock_exception_dialog_signal.connect(self.unlock)

    def lock(self):
        #print("ACQUIRE LOCK")
        self.modal_dialog_active = True
        self.last_status = None

    @pyqtSlot(bool)
    def unlock(self, result):
        #print("UNLOCK")
        self.modal_dialog_active = False
        #print("Set window result to: {}".format(result))
        self.last_status = result

    def is_ready_for_dialog(self):
        return not self.modal_dialog_active

    def is_status_availiable(self):
        return self.last_status


    def get_current_learning_mode_flag(self):
        return self.parent.LEARNING_MODE

    def run(self):
        ee = exception_engine.ExceptionEngine(self.EXCEPTION_RULES)

        while True:
            al = self.SHOW_MQ.get()

            if ee.should_be_skipped(al):
                continue
            else:
                #LEARN AND WAIT
                if self.get_current_learning_mode_flag():
                    while True:
                        if self.is_ready_for_dialog():
                            self.lock()
                            self.show_add_exception_dialog.emit(al)

                            while True:
                                status = self.is_status_availiable()

                                # STILL NO ANSWER
                                if status is None:
                                    time.sleep(0.02)
                                else:
                                    #print(" USER CLICKED: {}".format(status))
                                    if status == False:
                                        self.alert_everyone(al)
                                    #else:
                                        #print("Add exception....")

                                    break
                            break
                        else:
                            time.sleep(0.02)
                else:
                    self.alert_everyone(al)

    def alert_everyone(self,al):
        self.TRAY_MQ.put(al)
        self.ALARM_MQ.put(al)
        self.MALWARE_MQ.put(al)


