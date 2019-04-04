from .parser import Parser
from feeders.structures import *

class parser_evtx_wmi_trace(Parser):
    capabilities = {'type': TYPE_LOG_EVENT,
                    "feeders_list": ['evtx_security']
                    }

    def init(self, CONTAINERS=None, GATHERING_OPTIONS=None):
        self.CONTAINERS = CONTAINERS
        self.GATHERING_OPTIONS = GATHERING_OPTIONS

    def create_alert(self, pass_mq):
        # GRAB EVENT
        er = pass_mq.data
        alout = None

        #WMI
        if er.get_raw_field_event_id() == 4662:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                #EXCEPTIONS
                if er_fields['ObjectServer'].lower() != 'wmi' and er_fields['ObjectType'].lower() != "wmi namespace" and er_fields['ObjectName'].upper() != "ROOT\CIMV2":
                    return False

                # TITLE/Body
                title = "WMI unknown"

                AdditionalInfo_lower = er_fields['AdditionalInfo'].lower()
                AdditionalInfo2_lower = er_fields['AdditionalInfo2'].lower()

                #LOCAL READ
                local_remote = "Unknown"
                if AdditionalInfo_lower.find("remote read") != -1:
                    local_remote = "Remote"
                elif AdditionalInfo_lower.find("local read") != -1:
                    local_remote = "Local"
                else:
                    return False

                # REMOTE READ - TYPE
                    # ConnectServer
                body = ""
                body += "Invoked by: {}\\{}\n".format(er_fields['SubjectDomainName'], er_fields['SubjectUserName'])

                # SKIP WmiPerfClass
                if AdditionalInfo2_lower.find("wmiperfclass") != -1:
                    return False

                if AdditionalInfo_lower.find("connectserver") != -1:
                    title = "WMI {} client connected".format(local_remote)
                    body += "Namespace: {}\n".format(er_fields['AdditionalInfo2'])
                elif AdditionalInfo_lower.find("execquery") != -1:
                    title = "WMI {} query executed".format(local_remote)
                    body += "Query: {}\n".format(er_fields['AdditionalInfo2'])
                elif AdditionalInfo_lower.find("getobject") != -1:
                    title = "WMI {} object sent".format(local_remote)
                    body += "Object: {}\n".format(er_fields['AdditionalInfo2'])

                # ADD LOGON ID INFO
                #logon_info = get_logon_id_info(SubjectLogonId)

                #desc += logon_info

                # WAIT 1 SEC TO GATHER ADDITIONAL INFO
                '''if len(logon_info) == 0:
                    time.sleep(1)
                    logon_info = get_logon_id_info(SubjectLogonId)
                    desc += logon_info'''

                '''if len(logon_info) > 0:
                    desc += "Client IP: {}\n".format(logon_info[1])
                    desc += "Username: {}\n".format(logon_info[0])'''

                alout = alert(pass_mq, title, body)

        #if not alout is None:
            #print(alout)

        return alout

    def add_to_malware_report(self, pass_mq):
        pass