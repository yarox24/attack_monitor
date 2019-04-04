from .parser import Parser
from feeders.structures import *

class parser_evtx_sysmon_others(Parser):
    capabilities = {'type': TYPE_LOG_EVENT,
                    "feeders_list": ['evtx_sysmon']
                    }

    def init(self, CONTAINERS=None, GATHERING_OPTIONS=None):
        self.CONTAINERS = CONTAINERS
        self.GATHERING_OPTIONS = GATHERING_OPTIONS


    def create_alert(self, pass_mq):
        # GRAB EVENT
        er = pass_mq.data
        alout = None

        #Event ID 6: Driver loaded
        if er.get_raw_field_event_id() == 6:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:

                # TITLE
                title = "Driver loaded"

                # BODY
                body = ""

                body += "Path: {}\n".format(er_fields['ImageLoaded'])
                body += "Signed: {}\n".format(er_fields['Signed'])
                body += "Signature: {} ({})\n".format(er_fields['Signature'], er_fields['SignatureStatus'])
                body += "Hashes: {}\n".format(er_fields['Hashes'])

                alout = alert(pass_mq, title, body)

        #Event ID 8: CreateRemoteThread
        if er.get_raw_field_event_id() == 8:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                TargetImage = er_fields['TargetImage']
                DestinationName = TargetImage.split("\\")[-1]

                # TITLE
                title = "Remote thread created in {}".format(DestinationName)

                # BODY
                body = ""

                body += "Source: {} ({})\n".format(er_fields['SourceImage'], er_fields['SourceProcessId'])
                body += "Target: {} ({})\n".format(er_fields['TargetImage'], er_fields['TargetProcessId'])
                body += "Start Module: {} / {}\n".format(er_fields['StartModule'], er_fields['StartFunction'])
                body += "Start Address: {}\n".format(er_fields['StartAddress'])

                alout = alert(pass_mq, title, body)

        #Event ID 9: RawAccessRead
        if er.get_raw_field_event_id() == 9:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:

                # TITLE
                title = "Raw disk read - ".format(er_fields['Device'])

                # BODY
                body = ""
                body += "Source: {} ({})\n".format(er_fields['Image'], er_fields['ProcessId'])

                alout = alert(pass_mq, title, body)

        #Event ID 10: ProcessAccess
        # Too noisy
        '''if er.get_raw_field_event_id() == 10:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=False)
            if success:
                TargetImage = er_fields['TargetImage']
                DestinationName = TargetImage.split("\\")[-1]

                # TITLE
                title = "Process access process (Target: {})".format(DestinationName)

                # BODY
                body = ""
                body += "Source: {} ({})\n".format(er_fields['SourceImage'], er_fields['SourceProcessId'])
                body += "Target: {} ({})\n".format(er_fields['TargetImage'], er_fields['TargetProcessId'])
                body += "Granted Access: {} \n".format(er_fields['GrantedAccess']) # https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html
                body += "Call trace: {} \n".format(er_fields['CallTrace'])

                alout = alert(pass_mq, title, body)'''

        #Event ID 12: RegistryEvent (Object create and delete)
        if er.get_raw_field_event_id() == 12:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:

                #Delete/Created?
                event_type = "created"
                if er_fields['EventType'] == 'DeleteKey':
                    event_type = "deleted"


                # TITLE
                title = "Registry key {}".format(event_type)

                # BODY
                body = ""

                body += "Key: {}\n".format(er_fields['TargetObject'])
                body += "Image: {} ({})\n".format(er_fields['Image'], er_fields['ProcessId'])

                alout = alert(pass_mq, title, body)

        #Event ID 13: RegistryEvent (Value Set)
        if er.get_raw_field_event_id() == 13:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:

                # Delete/Created?
                event_type = "created"
                if er_fields['EventType'] == 'DeleteKey':
                    event_type = "deleted"

                # TITLE
                title = "Registry key value set".format()

                # BODY
                body = ""

                body += "Key: {}\n".format(er_fields['TargetObject'])
                body += "Value: {}\n".format(er_fields['Details'])
                body += "Image: {} ({})\n".format(er_fields['Image'], er_fields['ProcessId'])

                alout = alert(pass_mq, title, body)

        #Event ID 14: RegistryEvent (Key and Value Rename)
        if er.get_raw_field_event_id() == 14:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # Key/Value?
                event_type = "key"

                # NOT TESTED
                if er_fields['EventType'] != 'RenameKey':
                    event_type = "value"

                # TITLE
                title = "Registry {} renamed".format(event_type)

                # BODY
                body = ""

                body += "New Name: {}\n".format(er_fields['NewName'])
                body += "Old Name: {}\n".format(er_fields['TargetObject'])
                body += "Image: {} ({})\n".format(er_fields['Image'], er_fields['ProcessId'])

                alout = alert(pass_mq, title, body)

        #Event ID 15: FileCreateStreamHash
        if er.get_raw_field_event_id() == 15:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=False)
            if success:
                # TITLE
                title = "Alternate Data Stream created"

                body = ""
                body += "ADS Path: {} \n".format(er_fields['TargetFilename'])
                body += "Source: {} ({})\n".format(er_fields['Image'], er_fields['ProcessId'])
                body += "Hash: {}\n".format(er_fields['Hash'])

                alout = alert(pass_mq, title, body)

        #Event ID 17: PipeEvent (Pipe Created)
        if er.get_raw_field_event_id() == 17:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=False)
            if success:
                # TITLE
                title = "Pipe Created - {}".format(er_fields['PipeName'])

                body = ""
                body += "Source: {} ({})\n".format(er_fields['Image'], er_fields['ProcessId'])

                alout = alert(pass_mq, title, body)

        #Event ID 18: PipeEvent (Pipe Connected)
        if er.get_raw_field_event_id() == 18:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=False)
            if success:
                # TITLE
                title = "Connected to pipe - {}".format(er_fields['PipeName'])

                body = ""
                body += "Source: {} ({})\n".format(er_fields['Image'], er_fields['ProcessId'])

                alout = alert(pass_mq, title, body)

        return alout

    def add_to_malware_report(self, pass_mq):
        pass