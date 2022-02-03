import json

from dynamite_nsm import utilities
from dynamite_nsm.services.base.config_objects.generic import Analyzers
from dynamite_nsm.services.base.config_objects.zeek.local_site import Script
from dynamite_nsm.services.base.config_objects.suricata.rules import Rule
from dynamite_nsm.services.zeek.config import lookup_script_definition
from dynamite_nsm.services.zeek.config import SiteLocalConfigManager
from dynamite_nsm.services.suricata.config import lookup_rule_definition
from dynamite_nsm.services.suricata.config import ConfigManager as SuricataConfigManager

env = utilities.get_environment_file_dict()

ZEEK_SCRIPTS = env.get('ZEEK_SCRIPTS')
SURICATA_CONFIG = env.get('SURICATA_CONFIG')


zeek_scripts = SiteLocalConfigManager(ZEEK_SCRIPTS).scripts
suricata_rules = SuricataConfigManager(SURICATA_CONFIG).rules


def find_undefined(analyzers: Analyzers):
    undefined_analyzers = []
    for analyzer in analyzers:
        lookup = None
        if isinstance(analyzer, Script):
            lookup = lookup_script_definition(analyzer.id)
        elif isinstance(analyzer, Rule):
            lookup = lookup_rule_definition(analyzer.id)
        if not lookup:
            undefined_analyzers.append(analyzer)
    return undefined_analyzers


def find_collisions(analyzers: Analyzers):
    collision_analyzers = []
    analyzer_ids = {}
    for analyzer in analyzers:
        if analyzer_ids.get(analyzer.id):
            analyzer_ids[analyzer.id] += 1
        else:
            analyzer_ids[analyzer.id] = 1

    for _id, count in analyzer_ids.items():
        if count > 1:
            collision_analyzers.append(analyzers.get(_id))
    return collision_analyzers


def find_undefined_rules():
    return find_undefined(suricata_rules)


def find_collision_rules():
    return find_collisions(suricata_rules)


def find_undefined_scripts():
    return find_undefined(zeek_scripts)


def find_collision_scripts():
    return find_collisions(zeek_scripts)


def organize_definitions(definitions_fp: str):
    definitions = dict(json.load(open(definitions_fp)))
    ordered_definitions = {}
    group_keys = set()
    for _, metadata in definitions.items():
        group_key = ''.join(sorted(metadata.get('categories')))
        group_keys.add(group_key)

    group_keys = sorted(list(group_keys), key=lambda k: len(k))

    for group_key in group_keys:
        for _id, metadata in definitions.items():
            test_key = ''.join(sorted(metadata.get('categories')))
            if test_key == group_key:
                ordered_definitions.update({_id: metadata})

    return ordered_definitions



for s in find_undefined_scripts():
    print(s)