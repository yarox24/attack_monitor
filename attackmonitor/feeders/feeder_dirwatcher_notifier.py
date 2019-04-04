from .feeder import Feeder
from .structures import *
from watchdog.observers.read_directory_changes import WindowsApiObserver as Observer
from watchdog.events import *
import pathlib
from utils import configer
import time
from utils.nicedate import NiceDate

#CAPTURE_DIR = get_capture_dir()

class DirectoryWatcher(FileSystemEventHandler):
    '''https://pythonhosted.org/watchdog/api.html#module-watchdog.events'''

    def __init__(self, options, configer, ultra_mq, source):
        super().__init__()

        #ULTRA MQ
        self.ultra_mq = ultra_mq
        self.source = source

        # SET OPTIONS
        self.dirpath = os.path.expandvars(options['dirpath'])

        self.recursive = options['recursive']
        self.file_moved = options['file_moved']
        self.file_modified = options['file_modified']
        self.file_created = options['file_created']
        self.file_deleted = options['file_deleted']
        self.dir_moved = options['dir_moved']
        self.dir_modified = options['dir_modified']
        self.dir_created = options['dir_created']
        self.dir_deleted = options['dir_deleted']

        # TIME COST
        self.filesize_read = options['filesize_read']

        # EXTENSION FILTER
        if type(options['extension_filter']) is str:
            self.extension_filter = configer.get_config_options(options['extension_filter'])
        elif type(options['extension_filter']) is list:
            self.extension_filter = options['extension_filter']
        else:
            self.extension_filter = None

        print("DirectoryWatcher added: {}".format(self.dirpath))

    def get_source(self):
        return self.source

    def add_to_ultra_mq(self, mq):
        self.ultra_mq.put(mq)

    def is_dir_valid(self):
        if os.path.isdir(self.dirpath):
            return True
        return False

    def should_read_filesize(self):
        return self.filesize_read

    def filter_extension_skip_current(self, event, src_check=False, dest_check=False):
        #src_path
        if src_check:
            if not self.extension_filter is None:
                extension = pathlib.PureWindowsPath(event.src_path).suffix.lower().lstrip('.')
                if not extension in self.extension_filter:
                    return True

        #dest_path
        if dest_check:
            if not self.extension_filter is None:
                extension = pathlib.PureWindowsPath(event.dest_path).suffix.lower().lstrip('.')
                if not extension in self.extension_filter:
                    return True

        return False

    def before_read_break(self):
        time.sleep(0.15)

    def on_created(self, event):
        event_date = NiceDate.get_now()
        object_type = None
        filesize = None

        #FILE
        if isinstance(event, FileCreatedEvent):
            #IS ENABLED
            if self.file_created == False:
                return

            #EXTENSION FILTER
            if self.filter_extension_skip_current(event, src_check=True):
                return

            # GO FILE
            object_type = 'file'
            if self.should_read_filesize():
                try:
                    self.before_read_break()
                    filesize = str(os.path.getsize(event.src_path))
                except OSError:
                    pass

        #DIR
        if isinstance(event, DirCreatedEvent):
            # IS ENABLED
            if self.dir_created == False:
                return

            #GO DIR
            object_type = 'dir'

        # FEED ULTRA MQ
        fs_mq = fs_change_event('on_created', object_type, event.src_path, None, filesize)
        pass_mq = mq(fs_mq, TYPE_FS_CHANGE, self.get_source(), event_date, generate_mq_key(fs_mq, self.get_source()), None)
        self.add_to_ultra_mq(pass_mq)

    def on_deleted(self, event):
        event_date = NiceDate.get_now()

        object_type = None

        #DIR
        # MISTAKENLY TAKEN AS FILE :/
        if isinstance(event, DirDeletedEvent):
            # IS ENABLED
            if self.dir_deleted == False:
                return

            object_type = 'dir'

        #FILE
        if isinstance(event, FileDeletedEvent):
            #IS ENABLED
            if self.file_deleted == False:
                return

            #EXTENSION FILTER
            if self.filter_extension_skip_current(event, src_check=True):
                return

            object_type = 'file'

        # FEED ULTRA MQ
        fs_mq = fs_change_event('on_deleted', object_type, event.src_path, None, None)
        pass_mq = mq(fs_mq, TYPE_FS_CHANGE, self.get_source(), event_date,generate_mq_key(fs_mq, self.get_source()), None)
        self.add_to_ultra_mq(pass_mq)

    def on_modified(self, event):
        event_date = NiceDate.get_now()
        object_type = None
        filesize = None

        #FILE
        if isinstance(event, FileModifiedEvent):
            #IS ENABLED
            if self.file_modified == False:
                return

            #EXTENSION FILTER
            if self.filter_extension_skip_current(event, src_check=True):
                return

            #GO FILE
            object_type = 'file'
            if self.should_read_filesize():
                try:
                    self.before_read_break()
                    filesize = str(os.path.getsize(event.src_path))
                except OSError:
                    pass


        #DIR
        if isinstance(event, DirModifiedEvent):
            # IS ENABLED
            if self.dir_modified == False:
                return

            #GO DIR
            object_type = 'dir'

        # FEED ULTRA MQ
        fs_mq = fs_change_event('on_modified', object_type, event.src_path, None, filesize)
        pass_mq = mq(fs_mq, TYPE_FS_CHANGE, self.get_source(), event_date, generate_mq_key(fs_mq, self.get_source()), None)
        self.add_to_ultra_mq(pass_mq)

    def on_moved(self, event):
        event_date = NiceDate.get_now()
        object_type = None
        filesize = None

        #FILE
        if isinstance(event, FileMovedEvent):
            #IS ENABLED
            if self.file_moved == False:
                return

            #EXTENSION FILTER
            if self.filter_extension_skip_current(event, src_check=True) and self.filter_extension_skip_current(event, dest_check=True):
                return

            # GO FILE
            object_type = 'file'

            if self.should_read_filesize():
                try:
                    self.before_read_break()
                    filesize = str(os.path.getsize(event.dest_path))
                except OSError:
                    pass

        #DIR
        if isinstance(event, DirMovedEvent):
            # IS ENABLED
            if self.dir_moved == False:
                return

            #GO DIR
            object_type = 'dir'

        # FEED ULTRA MQ
        fs_mq = fs_change_event('on_moved', object_type, event.dest_path, event.src_path, filesize)
        pass_mq = mq(fs_mq, TYPE_FS_CHANGE, self.get_source(), event_date, generate_mq_key(fs_mq, self.get_source()),None)
        self.add_to_ultra_mq(pass_mq)

    def is_recursive(self):
        return self.recursive

    def get_dirpath(self):
        return self.dirpath

class feeder_dirwatcher_notifier(Feeder):

    def getName(self):
        return "dirwatcher_notifier"

    def run(self):
        observer_global = Observer()

        #READ MONITORED DIRECTORIES CONFIG
        conf = configer.Config()
        monitored_directories_options = conf.get_config_options('monitored_directories.json')

        for options in monitored_directories_options:
            dw = DirectoryWatcher(options, conf, self.ultra_mq, self.getName())
            if dw.is_dir_valid():
                observer_global.schedule(dw, path=dw.get_dirpath(), recursive=dw.is_recursive())
            else:
                print("Invalid dirpath for monitoring: {}".format(dw.get_dirpath()))

        # START WATCHING
        observer_global.start()
        observer_global.join()
