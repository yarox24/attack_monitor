from PyQt5.QtWidgets import QDialog, QScrollArea, QWidget, QVBoxLayout
from PyQt5 import QtWidgets, QtCore
from exception_package import exception_engine
from collections import namedtuple
from feeders.structures import *

gui_control = namedtuple('gui_control', 'control_enabled control_check_type control_value orig_text')
gui_selection = namedtuple("gui_selection", "name check_type text_rule")

class ExceptionDialog(QDialog):

    def __init__(self, alert, APP, unlock_exception_dialog_signal, EXCEPTION_RULES):
        super().__init__()
        self.APP = APP
        self.alert = alert
        self.EXCEPTION_RULES = EXCEPTION_RULES

        self.setModal(True)
        screen_resolution = self.APP.desktop().screenGeometry()
        self.screen_width =screen_resolution.width()
        self.screen_height =  screen_resolution.height()
        self.unlock_exception_dialog_signal = unlock_exception_dialog_signal
        self.CONTROLS = dict()
        self.emited_once = False

        #EXCEPTION ENGINGE
        self.ee = exception_engine.ExceptionEngine(self.EXCEPTION_RULES)

        # CREATE BASED ON ALERT
        self.prepare_gui_for_alert()

    def append_control(self, name, gui_contr):
        self.CONTROLS[name] = gui_contr

    def show_dialog(self):
        #print("Ask for exception...")
        self.exec_()

    def prepare_gui_for_alert(self):

        # ALERT FIELDS
        title = self.alert.title
        body = self.alert.body
        mq = self.alert.enhanced_data

        #DATA
        data = mq.data
        source = mq.source
        mq_type = mq.type
        #key
        extra_data = mq.extra_data
        fields = merge_fields_alert(self.alert)

        # ALWAYS ENABLED FIELDS
        ALWAYS_ENABLED_FIELDS = ['source', 'eid']

        self.setSizeGripEnabled(False)
        self.setWindowTitle("Add exception - {}".format(title))

        # Wide XGA 1280 x 720
        MINIMUM_WIDTH = 1280 * 0.9
        MINIMUM_HEIGHT = 720 * 0.8
        SINGLE_ELEMENT_HEIGHT = 20

        NR_OF_ELEMENTS = len(fields)

        scrollarea = QScrollArea(self)

        calculated_height = NR_OF_ELEMENTS * (SINGLE_ELEMENT_HEIGHT + 14) + 30
        if calculated_height > self.screen_height - 100:
            calculated_height = self.screen_height - 100

        scrollarea.resize(MINIMUM_WIDTH, calculated_height)

        verticalLayoutWidget = QWidget()
        vertical_layout = QVBoxLayout(verticalLayoutWidget)

        # ADD FIELDS
        for name in fields.keys():
            try:
                value = fields[name]

                always_enabled = False
                if name in ALWAYS_ENABLED_FIELDS:
                    always_enabled = True

                horizontal_layout = QtWidgets.QHBoxLayout()
                horizontal_layout.alignmentRect(QtCore.QRect(0, 0, MINIMUM_WIDTH - 20, SINGLE_ELEMENT_HEIGHT))

                # CHECKBOX - DISABLED/ENABLED CHECK?
                checkbox = QtWidgets.QCheckBox()
                checkbox.setText(name)
                checkbox.setObjectName(name)

                if always_enabled:
                    checkbox.setEnabled(False)
                    checkbox.setChecked(True)

                checkbox.stateChanged.connect(self.enable_disable_tick)
                horizontal_layout.addWidget(checkbox)

                # COMBO BOX - REGEX/STRING/SUSBTR
                combobox_dynamic = QtWidgets.QComboBox()

                if type(value) is str:
                    for items in exception_engine.CHECK_METHOD:
                        nice_name, _ , index = items
                        combobox_dynamic.addItem(nice_name, index)
                elif type(value) is list:
                    equals_no_case = exception_engine.CHECK_METHOD[0]
                    combobox_dynamic.addItem(equals_no_case[0], equals_no_case[2])

                combobox_dynamic.setEnabled(False)
                combobox_dynamic.setObjectName(name)
                combobox_dynamic.currentIndexChanged.connect(self.check_type_changed)
                horizontal_layout.addWidget(combobox_dynamic)

                # TEXT INPUT or COMBOBOX
                dynamic = None
                if type(value) is str:
                    dynamic = QtWidgets.QLineEdit()
                    dynamic.setMinimumWidth(MINIMUM_WIDTH - 245)
                    dynamic.setText(self.ee.string_to_env(value))
                    dynamic.setEnabled(False)
                    dynamic.setObjectName(name)
                    dynamic.textEdited.connect(self.text_changed)

                elif type(value) is list:
                    dynamic = QtWidgets.QComboBox()
                    dynamic.setFixedWidth(MINIMUM_WIDTH - 265)
                    dynamic.setEnabled(False)
                    dynamic.setObjectName(name)
                    for elem in value:
                        dynamic.addItem(self.ee.string_to_env(elem))

                horizontal_layout.addWidget(dynamic)
                vertical_layout.addLayout(horizontal_layout)

                self.append_control(name, gui_control(checkbox, combobox_dynamic, dynamic, value))
            except Exception:
                pass

        # ADD BUTTONS
        horizontal_layout = QtWidgets.QHBoxLayout()
        horizontal_layout.alignmentRect(QtCore.QRect(0, 0, MINIMUM_WIDTH - 20, SINGLE_ELEMENT_HEIGHT))

        add_exception_button = QtWidgets.QPushButton()
        add_exception_button.setText("Add Exception")
        add_exception_button.clicked.connect(self.ok_clicked)
        add_exception_button.setAutoDefault(False)
        add_exception_button.setDefault(False)

        cancel_button = QtWidgets.QPushButton()
        cancel_button.setText("Cancel")
        cancel_button.clicked.connect(self.cancel_clicked)
        cancel_button.setAutoDefault(True)
        cancel_button.setDefault(True)

        horizontal_layout.addWidget(add_exception_button)
        horizontal_layout.addWidget(cancel_button)
        vertical_layout.addLayout(horizontal_layout)

        scrollarea.setWidget(verticalLayoutWidget)
        scrollarea.setWidgetResizable(True)

        self.adjustSize()
        self.setWindowFlags(QtCore.Qt.MSWindowsFixedSizeDialogHint | QtCore.Qt.Dialog | QtCore.Qt.WindowStaysOnTopHint)


    def get_gui_options(self):
        options = list()

        for name in self.CONTROLS.keys():
            gui_ctrl = self.CONTROLS[name]
            if gui_ctrl.control_enabled.isChecked():
                check_type = gui_ctrl.control_check_type.currentIndex()
                text = None

                if isinstance(gui_ctrl.control_value, QtWidgets.QLineEdit):
                    text = gui_ctrl.control_value.text()
                elif isinstance(gui_ctrl.control_value, QtWidgets.QComboBox):
                    text = gui_ctrl.control_value.currentText()

                options.append(gui_selection(name, check_type, text))

        return options

    def enable_disable_tick(self):
        cb_name = self.sender().objectName()
        self.recalculate_row(cb_name)

    def check_type_changed(self):
        ct_name = self.sender().objectName()
        self.recalculate_row(ct_name)

    def text_changed(self):
        text_name = self.sender().objectName()
        self.recalculate_row(text_name)

    def recalculate_row(self, name):

        gui_contr = self.CONTROLS[name]

        # IF ENABLED
        if gui_contr.control_enabled.isChecked():
            gui_contr.control_check_type.setEnabled(True)
            gui_contr.control_value.setEnabled(True)

            check_type = gui_contr.control_check_type.currentIndex()

            # LINEEDIT CHECK
            if isinstance(gui_contr.control_value, QtWidgets.QLineEdit):
                original_text = gui_contr.orig_text
                if self.ee.check_text(check_type, gui_contr.control_value.text(), original_text):
                    gui_contr.control_value.setStyleSheet("background-color: rgba(46, 204, 113, 255);")
                else:
                    # BAD
                    gui_contr.control_value.setStyleSheet("background-color: rgba(206, 21, 19, 255);")

        else:
            gui_contr.control_check_type.setEnabled(False)
            gui_contr.control_value.setEnabled(False)

            if isinstance(gui_contr.control_value, QtWidgets.QLineEdit):
                gui_contr.control_value.setStyleSheet("")

    def emit_once(self, status):
        if not self.emited_once:
            self.unlock_exception_dialog_signal.emit(status)
            self.emited_once = True

    def cancel_clicked(self):
        self.reject()
        self.emit_once(False)

    def ok_clicked(self):
        self.accept()
        self.add_exception()
        self.emit_once(True)

    def add_exception(self):
        options = self.get_gui_options()
        if len(options) >= 1:
            self.ee.add_exception(options, self.alert.enhanced_data.key)
        else:
            print("Not enough options to add exception")

    # X Clicked
    def closeEvent(self, event):
        self.cancel_clicked()
