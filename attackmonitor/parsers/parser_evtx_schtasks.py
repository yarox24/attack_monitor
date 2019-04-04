from .parser import Parser
from feeders.structures import *
import re

class parser_evtx_schtasks(Parser):
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

        # Scheduled task was created.
        if er.get_raw_field_event_id() == 4698:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "Scheduled task: {} was created".format(er_fields['TaskName'])

                # BODY
                cmd_extracted = ""

                matches = re.finditer(r"<Exec>(.*?)</Exec>", er_fields['TaskContent'], re.MULTILINE | re.IGNORECASE | re.DOTALL)

                command_list = list()
                for match in matches:
                    if match.groups():
                        cmd_extracted = match.group(1).replace("\n", " ").replace("\r", " ")
                        command_list.append(cmd_extracted)

                body = ""
                body += "By user {}\{}\n".format(er_fields['SubjectDomainName'], er_fields['SubjectUserName'])
                body += "Command: {}\n".format(";".join(command_list))
                body += "Task XML: {}\n".format(er_fields['TaskContent'])

                alout = alert(pass_mq, title, body)

        #if not alout is None:
            #print(alout)

        return alout

    def add_to_malware_report(self, pass_mq):
        pass
