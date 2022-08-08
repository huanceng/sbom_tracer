# coding=utf-8
import importlib
import inspect
import os
import re

from sbom_tracer.local_analyzer.analyzer_base import AnalyzerBase
from sbom_tracer.util.const import PROJECT_NAME


class AnalyzerFactory(object):
    @classmethod
    def get_all_analyzers(cls):
        analyzers = []
        for f in os.listdir(os.path.abspath(os.path.dirname(__file__))):
            match = re.match("(.*)_analyzer.py", f)
            if match:
                analyzers.append(cls.get_analyzer(match.group(1)))
        return analyzers

    @classmethod
    def get_analyzer(cls, analyzer):
        module = importlib.import_module("{}.local_analyzer.{}_analyzer".format(PROJECT_NAME, analyzer))
        for name, clz in inspect.getmembers(module, inspect.isclass):
            if issubclass(clz, AnalyzerBase) and clz != AnalyzerBase:
                return clz
        raise Exception("invalid local analyzer: [{}]".format(analyzer))
