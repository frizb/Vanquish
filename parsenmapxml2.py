import xml.etree.ElementTree as ET

d = [
        {'path': 'address', 'el': 'addr'},
        {'path': 'hostnames/hostname', 'el': 'name'},
        {'path': 'os/osmatch/osclass', 'el': 'osfamily'},
        {'path': 'ports/port', 'el': 'portid'}
]

tree = ET.parse('Masscan.xml')
root = tree.getroot()
for i in root.iter('host'):
    for h in d:
        e = i.find(h['path'])
        if e is not None: print(e.get(h['el']))
    addresses = i.findall('address')