from .parser import Parser
from feeders.structures import *

class parser_evtx_powershell_scriptblock(Parser):
    capabilities = {'type': TYPE_LOG_EVENT,
                    "feeders_list": ['evtx_powershell_operational']
                    }

    def init(self, CONTAINERS=None, GATHERING_OPTIONS=None):
        self.CONTAINERS = CONTAINERS
        self.GATHERING_OPTIONS = GATHERING_OPTIONS

    def create_alert(self, pass_mq):
        # GRAB EVENT
        er = pass_mq.data
        alout = None

        # Execute a Remote Command
        if er.get_raw_field_event_id() == 4104:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "Powershell ScriptBlock executed"

                # BODY
                # VALUES Parsing
                ScriptBlockText = er_fields["ScriptBlockText"]
                MessageNumber = int(er_fields["MessageNumber"])
                MessageTotal = int(er_fields["MessageTotal"])

                body = "Code: {}".format(ScriptBlockText)

                #SHOW ONLY BLOCK 1
                if MessageNumber != 1:
                    return False

                #THERE IS MORE BLOCKS
                if MessageNumber != MessageTotal:
                    body += "Block: {}/{}".format(MessageNumber, MessageTotal)

                # SKIP KNOWN COMMANDS
                if ScriptBlockText == "prompt" or ScriptBlockText.find("{ Set-StrictMode -Version") != -1 or ScriptBlockText.find("\\v1.0\\profile.ps1") != -1:
                    return False

                alout = alert(pass_mq, title, body)

        #if not alout is None:
            #print(alout)

        return alout

    def add_to_malware_report(self, pass_mq):
        pass