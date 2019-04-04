
#XML
from xmltodict import parse
from io import StringIO
from pyexpat import ExpatError

from collections import OrderedDict


#Return dictionary
class XmlEventParser():

    def __init__(self, raw_xml):

        self.raw_xml = raw_xml
        self.dictio = dict()
        self.valid = False
        self.error = None

        try:
            str_io = StringIO(self.raw_xml)
            self.dictio = parse(self.raw_xml)
            self.remove_namespaces(self.dictio)
            if ('Event' in self.dictio.keys()):
                self.valid = True
            else:
                raise AssertionError
        except ExpatError as  ee:
            self.error = ee.__repr__()
        except Exception as e:
            self.error = e.__repr__()


    def remove_namespaces(self, d):
        if isinstance(d, OrderedDict):
            for key, val in list(d.items()):
                #DELETE XMLNS
                if key.startswith("@xmlns"):
                    del d[key]
                else:
                    self.remove_namespaces(val)

    def is_valid(self):
        return self.valid

    def get_error(self):
        return self.error

    def get_dictionary(self):
        return self.dictio
