#!/usr/bin/env python3
"""Use the openchannel hook to selectively opt-into zeroconf
"""

from pyln.client import Plugin

plugin = Plugin()


@plugin.hook('openchannel')
def on_openchannel(openchannel, plugin, **kwargs):
    plugin.log(repr(openchannel))
    mindepth = int(plugin.options['zeroconf-mindepth']['value'])

    if openchannel['id'] == plugin.options['zeroconf-allow']['value']:
        plugin.log("This peer is in the zeroconf allowlist, setting mindepth=2")
        return {'result': 'continue', 'mindepth': mindepth}
    else:
        return {'result': 'continue'}


plugin.add_option(
    'zeroconf-allow',
    'A node_id to allow zeroconf channels from',
    '03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f'
)

plugin.add_option(
    'zeroconf-mindepth',
    0,
    'Number of confirmations to require from allowlisted peers',
)

plugin.run()
