from .feeder import *
from feeders.structures import *
from utils.nicedate import NiceDate
import pyshark
from pyshark.capture.capture import TSharkCrashException

import sys

class feeder_tshark(Feeder):

    def getName(self):
        return 'network_tshark'

    def run(self):
        INTERFACE_NAME = self.get_config_option("network_interface")
        if INTERFACE_NAME is None:
            print("You didn't specify network_inteface in configuration file for feeder_tshark plugin.")
            sys.exit(0)
        elif INTERFACE_NAME == "any":
            INTERFACE_NAME = None

        try:
            cap = pyshark.LiveCapture(interface=INTERFACE_NAME, bpf_filter="udp port 53")

        # NOT WORKING
        except Exception:
            print("Cannot start capturing events with tshark. Interface choosen: {}".format(INTERFACE_NAME))
            sys.exit(0)

        try:
            for packet in cap.sniff_continuously():
                pass_mq = mq(packet, TYPE_NETWORK_PACKET, self.getName(), NiceDate.naive_datetime_localize(packet.sniff_time), generate_mq_key(packet, None), None)
                self.add_to_ultra_mq(pass_mq)
                self.global_break()

        # NOT WORKING
        except Exception as ts:
            print("Error when capturing events with tshark. Interface choosen: {}".format(INTERFACE_NAME))
            print(ts)
            sys.exit(0)

# 'add_field', 'all_fields', 'alternate_fields', 'base16_value', 'binary_value',
            # 'capitalize', 'center', 'count', 'decode', 'encode', 'endswith',
            # 'expandtabs', 'fields', 'find', 'format', 'get_default_value',
            # 'hex_value', 'hide', 'index', 'int_value', 'isalnum', 'isalpha',
            # 'isdigit', 'islower', 'isspace', 'istitle', 'isupper', 'join',
            # 'ljust', 'lower', 'lstrip', 'main_field', 'name', 'partition',
            # 'pos', 'raw_value', 'replace', 'rfind', 'rindex', 'rjust',
            # 'rpartition', 'rsplit', 'rstrip', 'show', 'showname',
            # 'showname_key', 'showname_value', 'size', 'split',
            # 'splitlines', 'startswith', 'strip', 'swapcase',
            # 'title', 'translate', 'unmaskedvalue', 'upper',
            # 'zfill']
