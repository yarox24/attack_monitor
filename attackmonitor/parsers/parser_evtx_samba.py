from .parser import Parser
from feeders.structures import *

# FALSE - Supported but ignore
# NONE - Not supported

def flatten(text):
    return text.replace("\n", "").replace("\t", " ") .replace(" ", "")

class parser_samba_evtx(Parser):
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

        # Logon success

        #Detailed File Share
        if er.get_raw_field_event_id() == 5145:
            (success, er_resolved_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            (success, er_raw_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=False)
            if success:
                # TITLE LOW

                # BODY
                username = er_resolved_fields["SubjectUserName"]
                domain = er_resolved_fields["SubjectDomainName"]
                src_ip = er_resolved_fields["IpAddress"]
                src_port = er_resolved_fields["IpPort"]
                source_concat = src_ip + ":" + src_port
                share_name = er_resolved_fields["ShareName"]
                relative_path = er_resolved_fields["RelativeTargetName"]
                accesslist = er_raw_fields["AccessList"]
                accesslist_resolved = er_resolved_fields["AccessList"]
                accessmask = er_resolved_fields["AccessMask"]

                smb_optimized_path = share_name + "\\" + relative_path

                action = "unknown action"

                # SKIP LOCAL EVENTS
                #if src_ip in self.local_ips:
                    #return True

                if accesslist.find("%%1538") != -1 and accesslist.find("%%1541") != -1 and accesslist.find("%%4416") != -1 \
                    and accesslist.find("%%4417") != -1 and accesslist.find("%%4418") != -1 and accesslist.find(
                    "%%4419") != -1   and accesslist.find("%%4420") != -1 and accesslist.find("%%4423") != -1 and \
                    accesslist.find("%%4424") != -1 and relative_path.lower().find("srvsvc") != -1:
                    action = 'net view'

                    # SHOW ONLY ONCE
                    #if source_concat in self.net_view_exceptions:
                        #return True
                    #else:
                        #self.net_view_exceptions.add(source_concat)

                elif accesslist.find("%%1541") != -1 and accesslist.find("%%4416") != -1 and accesslist.find("%%4423") != -1:
                    #SKIP LISTING
                    #print("{},{},{}.{}".format(action, smb_optimized_path, flatten(accesslist), flatten(accessmask)))
                    return False
                elif accesslist.find("%%1537") != -1 and accesslist.find("%%1541") != -1 and accesslist.find("%%4423") != -1:
                    action = 'delete'
                elif accesslist.strip() == "%%4416".strip() != -1:
                    action = 'read'
                elif accesslist.find("%%4417") != -1:
                    action = 'write'

                    #IGNORE WRITE TO $IPC
                    if share_name.upper().find("$IPC") != -1:
                        return False
                elif accesslist.find("%%1541") != -1 and accesslist.find("%%4423") != -1:
                    action = 'listing'

                # UNKNOWN ACTION
                if action == "unknown action":
                    #print("[SMB Skip] {},{},{},{}".format(action, smb_optimized_path, flatten(accesslist), flatten(accessmask)))
                    return False

                # TITLE
                title = "SMB {} by: {}\{}".format(action, username, domain)

                body = 'Path: {}\n'.format(smb_optimized_path)
                body += "Src. IP: {}:{}".format(src_ip,src_port)

                alout = alert(pass_mq, title, body)

        # A network share object was added.
        if er.get_raw_field_event_id() == 5142:
            (success, er_resolved_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "SMB share added: {}".format(er_resolved_fields['ShareLocalPath'])

                # BODY
                body = 'Username: {}\{}\n'.format(er_resolved_fields['SubjectDomainName'], er_resolved_fields['SubjectUserName'])
                body += "Share: {}".format(er_resolved_fields['ShareName'])
                #body += get_logon_id_info(SubjectLogonId, user=False)

                alout = alert(pass_mq, title, body)

        # A network share object was modified.
        if er.get_raw_field_event_id() == 5143:
            (success, er_resolved_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "SMB share modified: {}".format(er_resolved_fields['ShareLocalPath'])

                # BODY
                body = 'Username: {}\{}\n'.format(er_resolved_fields['SubjectDomainName'], er_resolved_fields['SubjectUserName'])
                body += "Share: {}\n".format(er_resolved_fields['ShareName'])

                if er_resolved_fields['OldRemark'] != er_resolved_fields['NewRemark']:
                    body += "Remark: {} -> {}\n".format(er_resolved_fields['OldRemark'], er_resolved_fields['NewRemark'])
                if er_resolved_fields['OldMaxUsers'] != er_resolved_fields['NewMaxUsers']:
                    body += "Max Users: {} -> {}\n".format(er_resolved_fields['OldMaxUsers'], er_resolved_fields['NewMaxUsers'])
                if er_resolved_fields['OldShareFlags'] != er_resolved_fields['NewShareFlags']:
                    body += "Flags: {} -> {}\n".format(er_resolved_fields['OldShareFlags'], er_resolved_fields['NewShareFlags'])
                if er_resolved_fields['OldSD'] != er_resolved_fields['NewSD']:
                    body += "Sec. desc.: {} -> {}\n".format(er_resolved_fields['OldSD'], er_resolved_fields['NewSD'])

                #desc += get_logon_id_info(SubjectLogonId, user=False)

                alout = alert(pass_mq, title, body)

        # A network share object was deleted.
        if er.get_raw_field_event_id() == 5144:
            (success, er_resolved_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "SMB share deleted: {}".format(er_resolved_fields['ShareLocalPath'])

                # BODY
                body = 'Username: {}\{}\n'.format(er_resolved_fields['SubjectDomainName'], er_resolved_fields['SubjectUserName'])
                body += "Share: {}".format(er_resolved_fields['ShareName'])

                #desc += get_logon_id_info(SubjectLogonId, user=False)

                alout = alert(pass_mq, title, body)

        #if not alout is None:
            #print(alout)

        return alout

    def add_to_malware_report(self, pass_mq):
        pass
