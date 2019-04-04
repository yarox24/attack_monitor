from utils import configer
import json
import os
import re
from feeders.structures import *

CHECK_METHOD = (
    ("Equals (no case)", 'equals_no_case', 0),
    ("Equals (case)", 'equals_case', 1),
    ("Substring (no case)", 'substring_no_case', 2),
    ("Substring (case)", 'substring_case', 3),
    ("Regex (Whole)", 'regex_whole', 4),
    ("Regex (Substring)", 'regex_substring', 5)
)

class ExceptionEngine():

    def __init__(self, EXCEPTION_RULES):
        self.EXCEPTION_RULES = EXCEPTION_RULES
        self.cc = configer.Config()
        self.REPLACE_VARIABLES = self.load_replace_variables(self.cc)
        self.EXCEPTION_BASEDIR = self.cc.get_exception_files_basedir()

    def should_be_skipped(self, al):
        key = al.enhanced_data.key

        for rule in self.EXCEPTION_RULES[:]:
            rule_key = list(rule.keys())[0]

            if rule_key == key:
                merged_fields = merge_fields_alert(al)

                all_matched = True
                for condition in rule[rule_key]:
                    name, check_type, text_rule = condition
                    if not name in merged_fields.keys():
                        all_matched = False
                        break

                    al_value = merged_fields[name]
                    if type(al_value) is str:
                        if not self.check_text(check_type, text_rule, al_value):
                            all_matched = False
                            break
                    elif type(al_value) is list:
                        if not self.check_list(check_type, text_rule, al_value):
                            all_matched = False
                            break
                    else:
                        pass
                        raise AssertionError
                if all_matched:
                    return True

        return False

    def string_to_env(self, s):
        temp = s
        for env_key in self.REPLACE_VARIABLES.keys():
            constant = self.REPLACE_VARIABLES[env_key]

            # Case insesitive replace
            temp = re.sub(re.escape(constant), lambda _: env_key, temp, flags=re.I)
        return temp

    def env_to_string(self, s):
        temp = s
        for env_key in self.REPLACE_VARIABLES.keys():
            constant = self.REPLACE_VARIABLES[env_key]

            # Case insesitive replace
            temp = re.sub(re.escape(env_key), lambda _: constant, temp, flags=re.I)
        return temp

    def load_replace_variables(self, cc):
        REPLACE_VARIABLES_PATH = cc.get_replace_variables_path()

        if os.path.exists(REPLACE_VARIABLES_PATH):
            return json.load(open(REPLACE_VARIABLES_PATH, 'r', encoding='utf8'))
        else:
            raise AssertionError

    def check_text(self, check_type, text_rule, text_orig_env):
        text_rule_env = self.env_to_string(text_rule)

        if check_type == 0:
            return self.check_equals_nocase(text_rule_env, text_orig_env)
        elif check_type == 1:
            return self.check_equals_case(text_rule_env, text_orig_env)
        elif check_type == 2:
            return self.check_substrings_nocase(text_rule_env, text_orig_env)
        elif check_type == 3:
            return self.check_substrings_case(text_rule_env, text_orig_env)
        elif check_type == 4:
            return self.check_regex_whole(text_rule_env, text_orig_env)
        elif check_type == 5:
            return self.check_regex_substring(text_rule_env, text_orig_env)
        else:
            raise AssertionError

    def check_list(self, check_type, text_rule, list_orig):
        text_rule_env = self.env_to_string(text_rule)

        if check_type == 0:
            for elem in list_orig:
                if self.check_equals_nocase(text_rule_env, elem):
                    return True
        else:
            raise AssertionError
        return False



    def check_equals_nocase(self, text_rule, tested_value):
        if text_rule.upper().lower() == tested_value.upper().lower():
            return True
        return False

    def check_equals_case(self, text_rule, tested_value):
        if text_rule == tested_value:
            return True
        return False

    def check_substrings_nocase(self, text_rule, tested_value):
        if len(text_rule) == 0:
            return False

        if text_rule.upper().lower() in tested_value.upper().lower():
            return True
        return False

    def check_substrings_case(self, text_rule, tested_value):
        if len(text_rule) == 0:
            return False

        if text_rule in tested_value:
            return True
        return False

    def check_regex_whole(self, text_rule, tested_value):
        if len(text_rule) == 0:
            return False

        try:
            if re.match(text_rule, tested_value, flags=re.IGNORECASE):
                return True
        except re.error:
            pass
        return False

    def check_regex_substring(self, text_rule, tested_value):
        if len(text_rule) == 0:
            return False

        try:
            if re.search(text_rule, tested_value, flags=re.IGNORECASE):
                return True
        except re.error:
            pass
        return False

    def __options_to_rule(self, exception_key, options):
        rule = list()

        for gui_sel in options:
            rule.append((gui_sel.name, gui_sel.check_type, self.string_to_env(gui_sel.text_rule),))
        return {exception_key : rule}

    def save_exceptions(self):
        exception_brach_out = "{}{}.json".format(self.EXCEPTION_BASEDIR, "exceptions")

        with open(exception_brach_out, 'w', encoding='utf8') as outfile:
            str_ = json.dumps(self.EXCEPTION_RULES[:], indent=4, separators=(',', ': '), ensure_ascii=False)
            outfile.write(str_)


    def add_exception(self, options, exception_key):
        self.EXCEPTION_RULES.append(self.__options_to_rule(exception_key, options))
        self.save_exceptions()
