from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import QThread, QObject, pyqtSignal, pyqtSlot

from feeders.structures import alert
from .exception_dialog import ExceptionDialog
from utils import configer
from guidir.system_tray_icon import SystemTrayIcon
from guidir.exception_worker import QTExceptionWorker
from guidir.tray_worker import QTTrayWorker


class GUI(QtWidgets.QMainWindow):

    unlock_exception_dialog_signal = pyqtSignal(bool)

    def __init__(self, app, SHOW_MQ, TRAY_MQ, ALARM_MQ, MALWARE_MQ, EXCEPTION_RULES):
        QtWidgets.QMainWindow.__init__(self)
        self.app = app
        self.some_widget = QtWidgets.QWidget()
        screen_resolution = self.app.desktop().screenGeometry()
        self.screen_width, self.screen_height = screen_resolution.width(), screen_resolution.height()
        self.dialog_controls = dict()
        self.SHOW_MQ = SHOW_MQ
        self.TRAY_MQ = TRAY_MQ
        self.ALARM_MQ = ALARM_MQ
        self.MALWARE_MQ = MALWARE_MQ
        self.EXCEPTION_RULES = EXCEPTION_RULES

        # GET GUI CONFIG
        self.cc = configer.Config()
        gui_options = self.cc.get_config_single_category(configer.MAIN_CONFIG, "gui")
        if gui_options['learning_mode']:
            self.LEARNING_MODE = True
        else:
            self.LEARNING_MODE = False

    @pyqtSlot(alert)
    def show_alert(self, alert):
        #print("SIGNALED: {}".format(alert))
        self.show_message(alert.title, alert.body)
        #time.sleep(1)

    def initialize_system_tray(self):
        self.trayIcon = SystemTrayIcon(QtGui.QIcon("icon\\attack_156413_1280_aMk_icon.ico"), self.some_widget, self, self.LEARNING_MODE)
        self.trayIcon.show()

    def set_learning_mode(self, checked):
        self.LEARNING_MODE = checked
        print("Learning mode changed to: {}".format(self.LEARNING_MODE))

    def show_message(self, title, body):
        #print("show_message() - signaled")
        self.trayIcon.show_message(title, body, QtWidgets.QSystemTrayIcon.Critical)

    @pyqtSlot(alert)
    def show_add_exception_dialog(self, alert):
        #print("show_add_exception_dialog()")
        ed = ExceptionDialog(alert, self.app, self.unlock_exception_dialog_signal, self.EXCEPTION_RULES)
        ed.show_dialog()
        ed.close()

    def show_window(self):
        self.hide()

    def start_exception_worker(self):
        qexceptionworker = QTExceptionWorker(self.SHOW_MQ, self.TRAY_MQ, self.ALARM_MQ, self.MALWARE_MQ, self.EXCEPTION_RULES, self)
        qexceptionworker.start()

    def start_tray_worker(self):
        qtrayworker = QTTrayWorker(self.TRAY_MQ, self)
        qtrayworker.start()



