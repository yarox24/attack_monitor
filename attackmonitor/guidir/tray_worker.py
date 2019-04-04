from PyQt5 import QtCore
from PyQt5.QtCore import QThread, QObject, pyqtSignal, pyqtSlot
from feeders.structures import alert
import win32api
import pywintypes
import win32gui
import win32con

import time

class QTTrayWorker(QThread):
    show_alert_signal = pyqtSignal(alert)

    def __init__(self, TRAY_MQ, parent):
        QtCore.QThread.__init__(self, parent)
        self.TRAY_MQ = TRAY_MQ
        self.show_alert_signal.connect(parent.show_alert)

    def get_cursor_position(self):
        while(True):
            try:
                savedpos = win32api.GetCursorPos()
                return savedpos
            except pywintypes.error:
                time.sleep(1)

    def is_screensaver_running(self):
        return win32gui.SystemParametersInfo(win32con.SPI_GETSCREENSAVERRUNNING)

    def block_until_screensaver_is_off(self):
        while (True):
            if self.is_screensaver_running():
                time.sleep(2)
            else:
                break

    def block_until_mouse_activity(self):
        savedpos = self.get_cursor_position()

        while (True):
            self.block_until_screensaver_is_off()
            curpos = self.get_cursor_position()
            if savedpos != curpos:
                return
            time.sleep(0.05)


    def run(self):
        while True:
            al = self.TRAY_MQ.get()
            #print("RECEIVED FOR TRAY")
            self.block_until_mouse_activity()
            self.show_alert_signal.emit(al)
            time.sleep(2)



