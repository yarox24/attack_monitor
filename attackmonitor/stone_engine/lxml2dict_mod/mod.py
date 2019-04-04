# coding:utf-8
import lxml.etree
import json
from collections import OrderedDict


class LxmlEtreeToDictConvert(object):
    def __init__(self, ignore_namespace=False, expand_namespace=False,
                 dict_factory=dict):
        self.ignore_namespace = ignore_namespace
        self.expand_namespace = expand_namespace
        self.dict_factory = dict_factory

    def _handle_namespace(self, tag, prefix):
        if self.ignore_namespace:
            tag = tag[tag.find("}") + 1:]
        elif not self.expand_namespace:
            tag = "{}:{}".format(
                prefix, tag[tag.find("}") + 1:])
        return tag

    def _convert_type(self, input_str):
        pass

    def convert(self, root):
        stack = []
        result = self.dict_factory()

        stack.append((root, result))

        while stack:
            current_node, parent_result = stack.pop()

            tag = current_node.tag
            if not isinstance(tag, str):
                continue
            if current_node.prefix:
                tag = self._handle_namespace(tag, current_node.prefix)

            current_result = parent_result.setdefault(tag, self.dict_factory())

            # if the key exist and not a list, change it into a list
            if current_result:
                if not isinstance(current_result, list):
                    current_result = [current_result]
                    parent_result[tag] = current_result
                current_result.append(self.dict_factory())
                current_result = current_result[-1]

            for attr_name, attr_val in current_node.attrib.items():
                current_result["@" + attr_name] = attr_val

            text = current_node.text
            if text and text.strip():
                current_result["$"] = text

            for child in current_node.iterchildren(reversed=True):
                stack.append((child, current_result))

        return result


def convert(root):
    return LxmlEtreeToDictConvert().convert(root)
