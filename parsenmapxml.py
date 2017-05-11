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
    ports = i.iter('ports')
    if ports is not None: print(ports)
    for port in i.iter('ports'):
        print port
    for portleaf in port.iter('port'):
        print portleaf
    for portleaf in port.iter('port'):
        print portleaf