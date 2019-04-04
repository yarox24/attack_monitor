from multiprocessing import Process
from PyQt5 import QtCore, QtGui, QtWidgets
from guidir import gui_code
import sys

class GUI_Process(Process):

    def __init__(self, SHOW_MQ, TRAY_MQ, ALARM_MQ, MALWARE_MQ, EXCEPTION_RULES):
        super(Process, self).__init__()
        self.daemon = True
        self.SHOW_MQ = SHOW_MQ
        self.TRAY_MQ = TRAY_MQ
        self.ALARM_MQ = ALARM_MQ
        self.MALWARE_MQ = MALWARE_MQ
        self.EXCEPTION_RULES = EXCEPTION_RULES

    def run(self):
        # APP
        self.APP = QtWidgets.QApplication(sys.argv)
        self.APP.setQuitOnLastWindowClosed(False)
        self.gui_instance = gui_code.GUI(self.APP, self.SHOW_MQ, self.TRAY_MQ, self.ALARM_MQ, self.MALWARE_MQ, self.EXCEPTION_RULES)
        self.gui_instance.initialize_system_tray()
        self.gui_instance.show_window()
        self.gui_instance.start_exception_worker()
        self.gui_instance.start_tray_worker()
        # INFINITE LOOP
        self.APP.exec_()





