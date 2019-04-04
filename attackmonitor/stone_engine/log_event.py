from datetime import datetime
import sys
from collections import OrderedDict
import copy

#PACKAGE
from .xml_event_parser import XmlEventParser
from .evtx_description_manager import EvtxDescriptionManager

class LogEvent():
    edm = None
    ALLOWED_SOURCE_OS = [7, 8, 10, 2008, 2012, 2016]
    PARAM_BUCKETS = ['data', 'binary']

    def __init__(self, data, src_type="raw_xml", source_os=7):
        self.dictionary = None
        self.valid = None
        self.template_stat = None

        # SOURCE OS REQUIRED FOR PARAMS AND DESCRIPTION
        if not source_os in LogEvent.ALLOWED_SOURCE_OS:
            print("Critical error: get_event_description() - OS number: {} not allowed. Allowed values: [{}]".format(source_os, ','.join([str(k) for k in LogEvent.ALLOWED_SOURCE_OS])))
            sys.exit(-1)
        self.source_os = source_os

        #VARIABLES NONE
        self.param_bucket = None

        #OPTIONAL
        self.raw_xml = data

        if src_type == "raw_xml":
            xep = XmlEventParser(data)
            if xep.is_valid():
                self.valid = True
                self.dictionary = xep.get_dictionary()
            else:
                self.xml_error = xep.get_error()
        else:
            raise NotImplementedError

    def is_valid(self):
        return self.valid

    def get_xml_error(self):
        return self.xml_error

    def __get_event_dictionary(self):
        return self.dictionary

    #RAW FIELDS - NO ENHANCEMENT
    def __value_get(self, nested, name='#text'):
        #ORDERED DICT
        if isinstance(nested, OrderedDict):
            try:
                return nested[name]
            except KeyError:
                pass
        elif isinstance(nested, str):
            if name == '#text':
                return nested
        elif nested is None:
            pass
        else:
            raise AssertionError

    def get_raw_field_provider_name(self):
        try:
            return self.dictionary['Event']['System']['Provider']['@Name']
        except KeyError:
            pass

    def get_raw_field_provider_guid(self):
        try:
            return self.dictionary['Event']['System']['Provider']['@Guid']
        except KeyError:
            pass

    def get_raw_field_provider_eventsourcename(self):
        try:
            return self.dictionary['Event']['System']['Provider']['@EventSourceName']
        except KeyError:
            pass

    def get_raw_field_event_id(self):
        try:
            return int(self.__value_get(self.dictionary['Event']['System']['EventID']))
        except (KeyError, TypeError) as e:
            pass

    def get_raw_field_event_id_qualifier(self):
        try:
            return int(self.__value_get(self.dictionary['Event']['System']['EventID'], '@Qualifiers'))
        except (KeyError, TypeError) as e:
            pass

    def get_raw_field_version(self):
        try:
            return self.dictionary['Event']['System']['Version']
        except KeyError:
            pass

    def get_raw_field_level(self):
        try:
            return self.dictionary['Event']['System']['Level']
        except KeyError:
            pass

    def get_raw_field_task(self):
        try:
            return self.dictionary['Event']['System']['Task']
        except KeyError:
            pass

    def get_raw_field_opcode(self):
        try:
            return self.dictionary['Event']['System']['Opcode']
        except KeyError:
            pass

    def get_raw_field_keywords(self):
        try:
            return self.dictionary['Event']['System']['Keywords']
        except KeyError:
            pass

    def get_raw_field_correlation_activityid(self):
        try:
            return self.__value_get(self.dictionary['Event']['System']['Correlation'], '@ActivityID')
        except KeyError:
            pass

    def get_raw_field_correlation_related_activityid(self):
        try:
            return self.__value_get(self.dictionary['Event']['System']['Correlation'], '@RelatedActivityID')
        except KeyError:
            pass

    def get_raw_field_security_userid(self):
        try:
            return self.__value_get(self.dictionary['Event']['System']['Security'],'@UserID')
        except KeyError:
            pass

    def get_raw_field_time_created(self):
        try:
            return self.dictionary['Event']['System']['TimeCreated']['@SystemTime']
        except KeyError:
            pass

    def get_raw_field_event_recordid(self):
        try:
            return self.dictionary['Event']['System']['EventRecordID']
        except KeyError:
            pass

    def get_raw_field_execution_processid(self):
        try:
            return self.__value_get(self.dictionary['Event']['System']['Execution'], '@ProcessID')
        except KeyError:
            pass

    def get_raw_field_execution_threadid(self):
        try:
            return self.__value_get(self.dictionary['Event']['System']['Execution'], '@ThreadID')
        except KeyError:
            pass

    def get_raw_field_channel(self):
        try:
            return self.dictionary['Event']['System']['Channel']
        except KeyError:
            pass

    def get_raw_field_computer(self):
        try:
            return self.dictionary['Event']['System']['Computer']
        except KeyError:
            pass

    #TESTS

    def test_params(self, show):
        self.__generate_raw_param_data()

        '''if show:
            print("--- PARAMS (FINAL) ---")
            if self.param_bucket['processed']:
                print("[{}]".format("USERDATA/EVENTDATA - PROCESSED"))
            else:
                print("[{}]".format("USERDATA/EVENTDATA - NOOooooooooooooooT PROCESSED"))
            pp.pprint(self.param_bucket['data'])
            if len(self.param_bucket['binary']) > 0:
                print("[{}]".format("BINARY"))
                pp.pprint(self.param_bucket['binary'])
            print("--- END PARAMS ---")'''

        #pp.pprint(self.get_raw_param_all_dict())

        return

    def test_raw(self):
        print("Provider Name: {} | GUID: {} | SourceName: {}".format(self.get_raw_field_provider_name(), self.get_raw_field_provider_guid(), self.get_raw_field_provider_eventsourcename()))
        print("EventID: {} | Qualifer: {}".format(self.get_raw_field_event_id(), self.get_raw_field_event_id_qualifier()))
        print("Version: {}".format(self.get_raw_field_version()))
        print("Level: {}".format(self.get_raw_field_level()))
        print("Task: {}".format(self.get_raw_field_task()))
        print("OpCode: {}".format(self.get_raw_field_opcode()))
        print("Keywords: {}".format(self.get_raw_field_keywords()))
        print("Correlation activity ID: {} | Related: {}".format(self.get_raw_field_correlation_activityid(), self.get_raw_field_correlation_related_activityid()))
        print("Security UID: {}".format(self.get_raw_field_security_userid()))
        print("Time created: {}".format(self.get_raw_field_time_created()))
        print("Record ID: {}".format(self.get_raw_field_event_recordid()))
        print("Execution PID: {} | TID: {}".format(self.get_raw_field_execution_processid(), self.get_raw_field_execution_threadid()))
        print("Channel: {}".format(self.get_raw_field_channel()))
        print("Computer: {}".format(self.get_raw_field_computer()))
        print("")
        print("EXPANDED:")
        print("EID expanded: {}".format(self.get_expanded_event_id_with_qualifier()))
        print("Time: {}".format(self.get_expanded_field_time_created_tuple()))

    # EXPANDED FIELDS
    def get_expanded_event_id_with_qualifier(self):
        event_id = self.get_raw_field_event_id()
        qualifier = self.get_raw_field_event_id_qualifier()

        try:
            if qualifier is None or qualifier == "":
                return int(event_id)
            else:
                calc = (int(qualifier) << 16) + int(event_id)
                return str(calc)
        except TypeError:
            pass

    def get_expaned_event_id_list(self):
        eid_list = []

        #EID + VERSION
        eid_list.append(str(self.get_expanded_event_id_with_qualifier()))

        #EID without VERSION
        eid_without_version = self.get_raw_field_event_id()
        if not eid_without_version in eid_list:
            eid_list.append(str(eid_without_version))

        #EID LAST CHANCE
        lower_word = "lower_word;{}".format(eid_without_version)
        eid_list.append(str(lower_word))

        return eid_list



    def get_expanded_field_time_created_tuple(self):
        raw_time = self.get_raw_field_time_created()

        if not len(raw_time) == 30:
            raise AssertionError

        #00Z - always
        #Windows milliseconds to Python Microseconds, not enough precision in python datetime :/
        raw_time_without_end = raw_time[:-11]
        milliseconds = int(raw_time[-10:-1])
        d = datetime.strptime(raw_time_without_end + "+0000", "%Y-%m-%dT%H:%M:%S%z")
        return (d, milliseconds)


    # USERDATA / EVENTDATA

    def __determine_raw_param_data_branch(self):
        try:
            userdata_eventdata_key = [key for key in self.dictionary['Event'].keys() if key.lower() != 'system']
            if len(userdata_eventdata_key) == 1:
                return self.dictionary['Event'][userdata_eventdata_key[0]]
            else:
                raise AssertionError
        except KeyError:
            pass

    def __initalize_bucket(self, force=False):
        if self.param_bucket is None or force == True:
            self.param_bucket = dict()
            for bucket in LogEvent.PARAM_BUCKETS:
                self.param_bucket[bucket] = OrderedDict()

            return True #FIRST TIME GENERATION
        return False    #ALREADY GENERATED


    def __generate_raw_param_data_without_processing(self):
        if self.__initalize_bucket(force=True):
            self.param_bucket['processed'] = False
            self.param_bucket['data'] = self.__determine_raw_param_data_branch()

    def __generate_raw_param_data(self):
        try:
            if self.__initalize_bucket():
                self.param_bucket['processed'] = True
                #HELPER FUNCTIONS
                def add_variable(value, name=None, xtype="str", bucket="data", first_empty_element_ignore=False):
                    #PARAM_BUCKETS = ['data', 'binary']
                    ALLOWED_TYPES = ['str', 'list']

                    #BUCKET VALIDATE
                    if not bucket in LogEvent.PARAM_BUCKETS:
                        raise AssertionError

                    #TYPE VALIDATE
                    if not xtype in ALLOWED_TYPES:
                        raise AssertionError

                    # NONE TO ""
                    value_copy = value

                    #UNICODE FIX
                    if type(value_copy) is str:
                        value_copy = value_copy.replace("\u200e", "")

                    '''value_copy = None
                    if not value is None:
                        value_copy = value
                    else:
                        value_copy = ""
                    '''

                    #AUTONUMBERING
                    if name is None:
                        next_index = len(self.param_bucket[bucket].keys()) + 1
                        if bucket == "data":
                            name = "{}_{}".format('stoneparam', next_index)
                        elif bucket == "binary":
                            name = "{}_{}".format('binaryparam', next_index)
                        else:
                            raise AssertionError

                    #SET EMPTY TYPE
                    if not name in self.param_bucket[bucket].keys():
                        if xtype == "str":
                            self.param_bucket[bucket][name] = ""
                        elif xtype == "list":
                            self.param_bucket[bucket][name] = list()
                        else:
                            raise AssertionError

                    #ADD VALUE
                    if xtype == "str":
                        self.param_bucket[bucket][name] = value_copy
                    elif xtype == "list":
                        if not (first_empty_element_ignore and len(self.param_bucket[bucket][name]) == 0 and value is None):
                            self.param_bucket[bucket][name].append(value_copy)
                    else:
                        raise AssertionError

                def data_importer(starting_point, category):
                    detected_type = type(starting_point)

                    def determine_bucket_based_on_key(key):
                        BINARY_KEYS_LIST = ['binaryDataSize', 'binaryData', 'Binary']

                        if key in BINARY_KEYS_LIST:
                            return 'binary'
                        else:
                            return 'data'

                    if detected_type is list:
                        for elem in starting_point:
                            if isinstance(elem, OrderedDict):
                                data_importer(elem, category)
                            elif isinstance(elem, str):
                                add_variable(elem, bucket=category)
                            elif elem is None:
                                add_variable(None, bucket=category)
                            else:
                                raise AssertionError
                    elif detected_type is OrderedDict:
                        if ('@Name' in starting_point.keys() or '#text' in starting_point.keys()) and len([k.lower() for k in starting_point.keys() if k.lower() != '@name' and k!= '#text']) == 0:
                            name = None
                            value = None
                            if '@Name' in starting_point.keys():
                                name = starting_point['@Name']
                            if '#text' in starting_point.keys():
                                value = starting_point['#text']
                            add_variable(value,name, bucket=category)
                        else:
                            for key in starting_point.keys():
                                val = starting_point[key]
                                if type(val) == str:
                                    add_variable(val, key, bucket=determine_bucket_based_on_key(key))
                                elif val is None:
                                    add_variable(None, key, bucket=category)
                                elif isinstance(val, OrderedDict):
                                    if len(val) == 1:
                                        nested1 = list(val.items())[0][1]
                                        if isinstance(nested1, list):
                                            for elem2 in nested1:
                                                add_variable(elem2, key, xtype='list', bucket=category)
                                        elif isinstance(nested1, str):
                                            add_variable(nested1, key, xtype='list', bucket=category)
                                        elif nested1 is None:
                                            add_variable(nested1, key, xtype='list', bucket=category, first_empty_element_ignore=True)
                                        else:
                                            raise AssertionError

                                    else:
                                        raise AssertionError

                                else:
                                    raise AssertionError


                    elif detected_type is str:
                        add_variable(starting_point, bucket=category)
                    elif starting_point is None:
                        raise AssertionError
                    else:
                        raise AssertionError


                # ----- END OF HELPER FUNCTIONS

                #BODY
                nested0 = self.__determine_raw_param_data_branch()

                #EMPTY PARAMS
                if nested0 is None or (len(nested0.keys()) == 1 and '@Name' in nested0.keys()):
                    return

                # CATEGORIES AS STRINGS
                all_strings = True
                for tup in nested0.items():
                    (key, item) = tup

                    if type(item) != str:
                        all_strings = False
                        break
                if all_strings == True:
                    for tup in nested0.items():
                        (key, item) = tup
                        add_variable(item, key, bucket='data')
                    return

                for category in [k for k in nested0.keys() if not k.startswith("@")]:
                    category_lower = category.lower()
                    if category_lower == '@version':
                        raise AssertionError

                    nested_data = nested0[category]

                    #SKIP EMPTY
                    if nested_data is None:
                        continue

                    #GENERIC DATA IMPORTER
                    if category_lower == 'data':
                        data_importer(nested_data, 'data')
                    elif category_lower == 'binary':
                        data_importer(nested_data, 'binary')
                    else:
                        data_importer(nested_data, 'data')
        except AssertionError:
            self.__generate_raw_param_data_without_processing()
    #END

    def __convert_null(self, value, doit):
        if doit and value is None:
            return ""
        return value

    def __resolve_double_percentage(self, value, doit):
        if doit:
            self.__initalize_event_description_manager()
            return LogEvent.edm.resolve_double_percentage(value, self.get_raw_field_provider_name(),
                                                self.get_raw_field_provider_guid(), self.source_os,
                                                self.get_expaned_event_id_list(), self.get_raw_field_version())
        return value

    def __additional_processing(self, value, convert_null, resolve_double_percentage):
        val_temp = copy.copy(value)
        val_temp = self.__convert_null(val_temp, convert_null)
        val_temp = self.__resolve_double_percentage(val_temp, resolve_double_percentage)
        return val_temp

    def __is_processed(self):
        self.__generate_raw_param_data()
        return self.param_bucket['processed']

    def get_raw_param_by_key(self, key, convert_null=False, resolve_double_percentage=False):
        self.__generate_raw_param_data()

        try:
            if self.__is_processed():
                return tuple([True, self.__additional_processing(self.param_bucket['data'][key], convert_null, resolve_double_percentage)])
        except KeyError:
            pass

        return tuple([False, None])

    def get_raw_param_by_index(self, index, convert_null=False, resolve_double_percentage=False):
        self.__generate_raw_param_data()

        if self.__is_processed():
            try:
                key_list = list(self.param_bucket['data'].keys())
                key_name = key_list[index] # EXCEPTION
                return tuple([True, self.__additional_processing(self.param_bucket['data'][key_name], convert_null, resolve_double_percentage)])
            except IndexError:
                pass

        return tuple([False, None])

    def get_raw_param_all_dict(self, convert_null=False, resolve_double_percentage=False):
        self.__generate_raw_param_data()
        if self.__is_processed():
            out = OrderedDict()
            for key, val in self.param_bucket['data'].items():
                out[key] = self.__additional_processing(val, convert_null, resolve_double_percentage)
            return tuple([True, out])
        else:
            return tuple([False, self.param_bucket['data']])


    #DESCRIPTIONS
    def __initalize_event_description_manager(self):
        if LogEvent.edm is None:
            LogEvent.edm = EvtxDescriptionManager()

            #PROPERLY LOADED
            if not LogEvent.edm.is_database_loaded():
                print("Critical error: __initalize_event_description_manager() - Database of events not loaded due to unknown error")
                sys.exit(-1)

    # DESCRIPTION
    def get_event_description(self, force_os=None):
        self.__initalize_event_description_manager()

        find_os = self.source_os
        if not force_os is None:
            find_os = force_os

        desc = LogEvent.edm.get_event_description(
            self.get_raw_field_provider_name(), self.get_raw_field_provider_guid(), find_os,
            self.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True),
            self.get_expaned_event_id_list(), self.get_raw_field_version()
        )
        return desc
