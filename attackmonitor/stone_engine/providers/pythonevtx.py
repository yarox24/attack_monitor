from providers.evtx_provider import EvtxProvider
from .. import log_event
import sys

class pythonevtx(EvtxProvider):

    def iterate_over_records(self):
        pass

    def iterate_over_xml(self):
        #MAKE THIS LIB OPTIONAL
        try:
            import Evtx.Evtx as evtx
            import Evtx.Views as e_views
        except ImportError:
            print("Module python-evtx (williballenthin) is not installed")
            print("pip3 install --upgrade python-evtx")
            sys.exit(0)

        if self.is_valid():
            with evtx.Evtx(self.path) as log:
                for record in log.records():
                    try:
                        yield(True, None, record.xml())
                    except OSError as e:
                        yield (False, "Binary to XML conversion error: {} ".format(e.strerror), None)


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










