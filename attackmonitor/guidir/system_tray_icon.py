from PyQt5 import QtWidgets
import sys

class SystemTrayIcon(QtWidgets.QSystemTrayIcon):

    def __init__(self, icon, parent, main_app, learning_mode):
        self.main_app = main_app
        QtWidgets.QSystemTrayIcon.__init__(self, parent)
        self.setIcon(icon)
        menu = QtWidgets.QMenu(parent)

        #LEARNING MODE
        menu_learning_action = menu.addAction("Learning mode")
        menu_learning_action.setCheckable(True)
        menu_learning_action.setChecked(learning_mode)

        menu_learning_action.toggled.connect(self.main_app.set_learning_mode)

        menu.addSeparator()

        #EXIT
        exitAction = menu.addAction("Exit")
        exitAction.triggered.connect(self.exit_zero)

        self.setContextMenu(menu)

    def exit_zero(self, checked):
        sys.exit(0)

    def show_message(self, title, msg, icon):
        self.showMessage(title, msg, icon)

        #QtWidgets.QSystemTrayIcon.Critical
        #winsound.PlaySound('sound\\Buzz-SoundBible.com-1790490578.wav', 0)
