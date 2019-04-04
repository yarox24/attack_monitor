from providers.evtx_provider import EvtxProvider
from .. import log_event
import sys

class libevtx(EvtxProvider):

    def iterate_over_records(self):

        #MAKE THIS LIB OPTIONAL
        try:
            import pyevtx
        except ImportError:
            print("Module pyevtx (libyal/libevtx) is not installed")
            print("pip3 install --upgrade libevtx-python")
            sys.exit(0)

        if self.is_valid():
            evtx_file = pyevtx.file()

            #OPEN MMAP AS EVTX
            try:
                evtx_file.open_file_object(self.map)
            except IOError as e:
                yield (False, e.strerror, None)
                evtx_file.close()
                return

            # NORMAL EVENTS
            for i in range(0, evtx_file.get_number_of_records()):
                try:
                    # is_valid, error, record
                    yield (True, None, evtx_file.get_record(i))
                except Exception as error:
                    yield (False, "Error opening normal record with ID: {} / {}".format(i, error.args), None)

            # RECOVERED EVENTS
            if self.recovery:
                for record_index in range(0, evtx_file.number_of_recovered_records):
                    try:
                        yield (True, None, evtx_file.get_recovered_record(record_index))
                    except IOError as error:
                        yield (False, "Error opening recovered record with ID: {}".format(record_index, error.strerror), None)

    def iterate_over_xml(self):
        for triple in self.iterate_over_records():
            is_valid, error_msg, record = triple
            #RECORD TO XML
            if is_valid:
                try:
                    yield (True, None, record.get_xml_string())
                except OSError as e:
                    yield (False, "Cannot get_xml_string(): {}".format(e.strerror), None)
            else:
                yield triple

    def iterate_over_events(self):
        for triple in self.iterate_over_xml():
            is_valid, error_msg, xml = triple
            if is_valid:
                le = log_event.LogEvent(xml, src_type="raw_xml")
                if le.is_valid():
                    yield(True, None, le)
                else:
                    yield (False, "Cannot convert XML to LogRecord", None)
            else:
                yield triple








