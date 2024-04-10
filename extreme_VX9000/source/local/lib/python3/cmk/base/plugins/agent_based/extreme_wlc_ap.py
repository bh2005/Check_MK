#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# License: GNU General Public License v2
#
# Author: thl-cmk[at]outlook[dot]com
# URL   : https://thl-cmk.hopto.org
# Date  : 2018-01-16
#
# rewrite for Extreme VX
#
import time
from typing import Optional, Dict, List
from dataclasses import dataclass
from cmk.utils import debug

from cmk.base.plugins.agent_based.agent_based_api.v1 import (
    register,
    Service,
    check_levels,
    SNMPTree,
    startswith,
    Result,
    State,
    get_rate,
    GetRateError,
    get_value_store,
    IgnoreResultsError,
)
from cmk.base.plugins.agent_based.agent_based_api.v1.type_defs import (
    DiscoveryResult,
    CheckResult,
    StringTable,
)


@dataclass
class ExtremeWlcAp:
    MacAddress: str
    Name: str
    AdminState: str
    IpAddress: str
    Location: str
    # Clients: int
    # TxFrames: int
    # RxFrames: int


def _extreme_adminstate(state):
    names = {
        '1': 'online',
        '2': 'offline',
    }
    return names.get(state, 'unknown')


def parse_extreme_wlc_ap(string_table: List[StringTable]) -> Optional[Dict[str, ExtremeWlcAp]]:
    if debug.enabled():
        print(string_table)
        
    section = {}
    for ap in string_table:
        try:
#            ap_mac_address, ap_name_description, admin_state, ap_ip_address, ap_location = ap
            ap_mac_address, ap_name_description, admin_state= ap
        except ValueError:
            return

        section[f'{ap_mac_address}'] = ExtremeWlcAp(
            MacAddress=ap_mac_address,
            Name=ap_name_description,
            # Clients=int(number_of_clients),
            AdminState=admin_state,
            IpAddress=ap_ip_address,
            Location=ap_location,
            # TxFrames=int(tx_frames),
            # RxFrames=int(rx_frames),
        )

    if debug.enabled():
        print(section)
    return section


def discovery_extreme_wlc_ap(section: Dict[str, ExtremeWlcAp]) -> DiscoveryResult:
    if debug.enabled():
        print(section)
    for ap in section.keys():
        yield Service(item=ap, parameters={'ap_inv_mac': section[ap].MacAddress})


def check_extreme_wlc_ap(item, params, section: Dict[str, ExtremeWlcAp]) -> CheckResult:
    if debug.enabled():
        print(section)    
    not_found_state = params['state_not_found']
    metric_prefix = 'extreme_wlc_ap_'
    try:
        ap = section[item]
    except KeyError:
        yield Result(state=State(not_found_state), notice='Item not found in SNMP data')
        return

    if ap.AdminState != '1':
        yield Result(state=State.WARN, notice=f'Admin state: {_extreme_adminstate(ap.AdminState)}')
    else:
        yield Result(state=State.OK, notice=f'Admin state: {_extreme_adminstate(ap.AdminState)}')

    yield Result(state=State.OK, summary=f'Name: {ap.Name}')

    if raise_ingore_res:
        raise IgnoreResultsError('Initializing counters')


register.snmp_section(
    name='extreme_wlc_ap',
    parse_function=parse_extreme_wlc_ap,
    fetch=[
        SNMPTree(
            base='.1.3.6.1.4.1.388.50.1.4.2.1.1',  # wingStatsDevTable
            oids=[
                '1',  # wingStatsDevMac
                # '2',  # wingStatsDevType
                '3',  # wingStatsDevHostname
                # '4',  # wingStatsDevVersion
                # '5',  # wingStatsDevSerialNo
                # '6',  # wingStatsDevRfDomainName
                '7',  # wingStatsDevOnline
            ],
        ),
#        SNMPTree(
#            base='.1.3.6.1.4.1.388.50.1.4.2.25.1.1.1', # wingStatsRfdWlApInfoEntry
#            oids=[
#                 '1',  # wingStatsDevWlApInfoMac
#                 '9',  #wingStatsDevWlApInfoHostname
#                '13',  # wingStatsRfdWlApInfoIp
#                '11',  # wingStatsRfdWlApInfoLocation
#            ],
#        ),
    ],
    detect=startswith('.1.3.6.1.2.1.1.1.0', 'VX9000'),  # sysDescr
)

register.check_plugin(
    name='extreme_wlc_ap',
    service_name='AP %s',
    discovery_function=discovery_extreme_wlc_ap,
    check_function=check_extreme_wlc_ap,
    check_ruleset_name='extreme_wlc_ap',
    check_default_parameters={
        'state_not_found': 3,
    }
)
