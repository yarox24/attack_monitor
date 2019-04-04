from .parser import Parser
from feeders.structures import *

class parser_dirwatcher_notifier(Parser):
    capabilities = {'type': TYPE_FS_CHANGE,
                    "feeders_list": ['dirwatcher_notifier']
                    }

    def init(self, CONTAINERS=None, GATHERING_OPTIONS=None):
        self.CONTAINERS = CONTAINERS
        self.GATHERING_OPTIONS = GATHERING_OPTIONS

    def create_alert(self, pass_mq):
        # GRAB EVENT
        fsce = pass_mq.data
        alout = None

        # VARS
        filesize = fsce.filesize
        event_type = fsce.event_type
        event_nice = ""
        if event_type == "on_created":
            event_nice = "creation"
        elif event_type == "on_deleted":
            event_nice = "deleted"
        elif event_type == "on_modified":
            event_nice = "modified"
        elif event_type == "on_moved":
            event_nice = "moved"
        else:
            raise AssertionError
        new_path = fsce.new_path
        object_type = "Directory"
        if fsce.object_type == 'file':
            object_type = "File"
        old_path  = fsce.old_path

        title = "{} {}".format(object_type, event_nice)
        body = ""
        if not old_path is None:
            body += "{} -> ".format(old_path)
        body += "{}\n".format(new_path)
        if not filesize is None:
            body += "Size: {} B".format(filesize)

        alout = alert(pass_mq, title, body)

        return alout

    def add_to_malware_report(self, pass_mq):
        pass