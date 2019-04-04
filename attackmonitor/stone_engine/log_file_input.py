import pathlib
import os
from enum import Enum
from stone_engine.providers import libevtx, pythonevtx

class ParserType(Enum):
    EVTX_LIBEVTX = 1
    EVTX_PYTHONEVTX = 2

class LogFileInput():
    path = None
    parser_type = None
    valid = False
    error = None
    internal_parser = None
    recovery = None

    def __init__(self, path, parser_type=None, recovery=False):
        self.recovery = recovery

        #FILE
        if os.path.isfile(path):
            if os.path.getsize(path) > 0:
                self.path = path
            else:
                self.error = "0 size file"
        else:
            self.error = "Non-existing file"

        # PARSER DETECT/SET
        if parser_type is None:
            self.parser_type = self.detect_parser_type()
        elif isinstance(parser_type, ParserType):
            self.parser_type = parser_type

        # PARSER CHECK
        if not self.parser_type is None:

            # PREPARE EVERYTHING
            if self.parser_type == ParserType.EVTX_LIBEVTX:
                self.internal_parser = libevtx.libevtx(self.path, recovery=self.recovery)
                if self.internal_parser.is_signature_valid():
                    self.internal_parser.mmap_file()
                    if self.internal_parser.is_valid():
                        self.valid = True
                    else:
                        self.error = self.internal_parser.get_error()
                else:
                    self.error = "Invalid file format according to parser validation: {}".format(self.parser_type)
            elif self.parser_type == ParserType.EVTX_PYTHONEVTX:
                self.internal_parser = pythonevtx.pythonevtx(self.path, recovery=self.recovery)
                if self.internal_parser.is_signature_valid():
                    if self.internal_parser.is_valid():
                        self.valid = True
                    else:
                        self.error = self.internal_parser.get_error()
                else:
                    self.error = "Invalid file format according to parser validation: {}".format(self.parser_type)


        else:
            self.error = "Unsupported parser provided/detected"

    def is_valid(self):
        return self.valid

    def get_error(self):
        return self.error

    def yield_events(self):
        if self.is_valid():

            #LIBEVTX
            if self.parser_type == ParserType.EVTX_LIBEVTX:
                for triple in self.internal_parser.iterate_over_events():
                    is_valid, error_msg, le = triple
                    if is_valid:
                        yield(True, None, le)
                    else:
                        yield(triple)
            elif self.parser_type == ParserType.EVTX_PYTHONEVTX:
                for triple in self.internal_parser.iterate_over_events():
                    is_valid, error_msg, le = triple
                    if is_valid:
                        yield(True, None, le)
                    else:
                        yield(triple)
        else:
            print(self.get_error())


    def detect_parser_type(self):
        ext = pathlib.Path(self.path).suffix[1:].lower()
        if ext == "evtx":
            # AUTODETECT DEFAULT TO LIBEVTX for .evtx
            return  ParserType.EVTX_LIBEVTX
        return None



