import configparser
import os
import sys
import json

MAIN_CONFIG = "attack_monitor.cfg"

class Config:
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(Config, cls).__new__(cls)
        return cls.instance

    def __init__(self):
        self.BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
        self.CONFIG_DIR = self.BASE_DIR + "\\" + "config"

    def __load_config(self, config_filename):
        config_path = self.CONFIG_DIR + "\\" + config_filename
        if config_filename.split(".")[1].lower() == "cfg":
            parser = configparser.ConfigParser()
            parser.read(config_path)
            return {s:dict(parser.items(s)) for s in parser.sections()}
        elif config_filename.split(".")[1].lower() == "json":
            return json.load(open(config_path))
        elif config_filename.split(".")[1].lower() == "list":
            lines = [line.strip() for line in open(config_path).readlines() if len(line.strip()) > 0 and not line.startswith("#")]

            return lines
        else:
            raise ReferenceError

    def get_config_options(self, config_filename):
        return self.__load_config(config_filename)

    def get_exception_files_basedir(self):
        return self.CONFIG_DIR + "\\" + "exceptions" + "\\"

    def get_replace_variables_path(self):
        return self.CONFIG_DIR + "\\" + "replace_variables.json"

    def get_config_single_category(self, config_filename, category):
        sections = self.__load_config(config_filename)
        # CONVERT TRUE/FALSE STR TO BOOL

        # CONVERT TRUE/FALSE STR TO BOOL
        for section in sections.keys():
            for option in sections[section].keys():
                if type(sections[section][option]) is str:
                    if sections[section][option].lower() == 'true':
                        sections[section][option] = True
                    elif sections[section][option].lower() == 'false':
                        sections[section][option] = False

        try:
            return sections[category]
        except:
            return None

    def get_config_single_variable_from_category(self, config_filename, category, key):
        return self.get_config_single_category(config_filename, category)[key]

    def get_debug_log_directory(self):
        return self.BASE_DIR + "\\" + "debug_log" + "\\"

    def get_log_directory(self):
        logs_dir = self.get_config_single_variable_from_category(MAIN_CONFIG, "logs", "logs_dir")
        return os.path.normpath(self.BASE_DIR + "\\" + logs_dir + "\\")

    def get_font_path(self):
        return self.BASE_DIR + "\\fonts\\FreeSerif.ttf"

    def get_options_for_feeder(self, feeder_name):
        return self.get_config_single_category(MAIN_CONFIG, "feeder_{}".format(feeder_name))

