# Author: dhtfish98
# Copyright (c) 2026 dhtfish98
"""Bounded offline zone/service XML structure and exposure review."""
import ipaddress
import re
import xml.etree.ElementTree as ET
from .common import InputError, Report, filemap, mapping, sequence, string

LIMITS=['Permanent XML snapshots and declared active-zone names only; no runtime state, interface/source resolution, inter-zone priorities or effective packet path is proven.',
 'Rich rules, forwarding, protocol/helper/module definitions and non-port services are OPEN. Default target is OPEN rather than assumed restrictive.',
 'Service openings on a zone are explicit exposure findings for review; this is not a complete reachability or firewall simulator.']

def xml(text,label,root):
    if re.search(r'<!\s*(?:DOCTYPE|ENTITY)',text,re.I):raise InputError('XML DTD/entities prohibited')
    try:element=ET.fromstring(text)
    except ET.ParseError as exc:raise InputError(label+': '+str(exc)) from exc
    if element.tag!=root:raise InputError(label+' must have '+root+' root')
    stack=[(element,0)];count=0
    while stack:
        node,depth=stack.pop();count+=1
        if count>10000 or depth>32:raise InputError('XML depth/element limit exceeded')
        if node.tag in ('short','description') and (len(node) or node.attrib):
            raise InputError('short/description must be text-only elements without attributes')
        stack.extend((child,depth+1) for child in node)
    return element

def port(node,label):
    if len(node) or (node.text and node.text.strip()):raise InputError('port must be an empty element')
    if set(node.attrib)-{'port','protocol'}:raise InputError('unknown port attributes')
    protocol=node.get('protocol');value=node.get('port','')
    if protocol not in ('tcp','udp','sctp','dccp'):raise InputError('unsupported port protocol')
    if not re.fullmatch(r'\d{1,5}(?:-\d{1,5})?',value):raise InputError('invalid port/range')
    pieces=[int(p) for p in value.split('-')];low=pieces[0];high=pieces[-1]
    if not(1<=low<=high<=65535):raise InputError('invalid port range bounds')
    return low,high,protocol

def analyze(snapshot):
    mapping(snapshot,'snapshot');zones=filemap(snapshot.get('zones'),'zones');services=filemap(snapshot.get('services',{}),'services')
    active=sequence(snapshot.get('active_zones',[]),'active_zones');active={string(x,'active zone') for x in active}
    report=Report('FirewalldZoneAudit','All supplied zone XML and referenced services, explicit target, binding and exposure declarations')
    roots={name:xml(text,name,'service') for name,text in services.items()}
    if not active:report.add('active_coverage','OPEN','active_zones','No declared active-zone observation')
    for name in active:
        if name not in zones:report.add('active_coverage','OPEN',name,'Active zone XML missing')
    def service_ports(name,where):
        if name not in roots:report.add('service_reference','OPEN',where,'Service XML missing: '+name);return []
        result=[]
        for child in roots[name]:
            if child.tag=='port':result.append(port(child,name))
            elif child.tag in ('short','description'):pass
            else:report.add('service_semantics','OPEN',name,'Unsupported service element '+child.tag)
        if not result:report.add('service_ports','OPEN',name,'No supported port declarations')
        return result
    for name,text in zones.items():
        root=xml(text,name,'zone');target=root.get('target','default')
        if set(root.attrib)-{'target','version'}:report.add('zone_attributes','OPEN',name,'Unknown zone attributes')
        if target in ('DROP','%%REJECT%%'):report.add('default_target','PASS',name,'Explicit restrictive target '+target)
        elif target=='ACCEPT':report.add('default_target','FAIL',name,'Unrestricted default acceptance')
        elif target=='default':report.add('default_target','OPEN',name,'Implicit zone target semantics')
        else:raise InputError('invalid zone target')
        bindings=[];exposures=[]
        if root.text and root.text.strip():report.add('zone_text','OPEN',name,'Unexpected non-element zone content')
        for index,node in enumerate(root):
            where=name+':element:'+str(index)
            if node.tag in ('short','description'):continue
            if node.tag in ('port','service','interface','source') and (len(node) or (node.text and node.text.strip())):raise InputError('zone leaf elements must be empty')
            if node.tag=='port':exposures.append(port(node,where))
            elif node.tag=='service':
                if set(node.attrib)!={'name'} or not node.get('name'):raise InputError('invalid service reference')
                exposures.extend(service_ports(node.get('name'),where))
            elif node.tag=='interface':
                if set(node.attrib)!={'name'} or not node.get('name'):raise InputError('invalid interface binding')
                bindings.append(node.get('name'))
                if any(c in node.get('name') for c in '*?['):report.add('binding','OPEN',where,'Wildcard interface binding')
            elif node.tag=='source':
                if set(node.attrib)=={'address'}:
                    try:network=ipaddress.ip_network(node.get('address'),strict=False)
                    except ValueError as exc:raise InputError('invalid source address') from exc
                    bindings.append(str(network))
                    if network.prefixlen==0:report.add('binding','OPEN',where,'All-address source binding')
                elif set(node.attrib)=={'mac'} or set(node.attrib)=={'ipset'}:report.add('binding','OPEN',where,'MAC/ipset scope not resolved')
                else:report.add('binding','OPEN',where,'Unsupported source attributes')
            elif node.tag in ('masquerade','forward-port','forward'):
                report.add('forwarding','OPEN',where,'Forwarding/NAT policy requires topology review')
            elif node.tag=='rule':report.add('rich_rule','OPEN',where,'Rich-rule packet semantics not evaluated')
            else:report.add('zone_semantics','OPEN',where,'Unsupported zone element '+node.tag)
        if name in active and not bindings:report.add('binding','OPEN',name,'Active-zone bindings absent; default-zone assignment may apply')
        seen=set()
        for low,high,protocol in exposures:
            key=(low,high,protocol)
            report.check('duplicate_exposure',key not in seen,name,'Duplicate zone/service port declaration '+repr(key));seen.add(key)
            report.check('port_range',high-low<1000,name,'Broad port range '+repr(key))
            report.add('service_exposure','OPEN',name,'Declared opening '+repr(key)+'; source reachability is not simulated')
    if not zones:report.add('coverage','OPEN','zones','No zones supplied')
    return report.finish(LIMITS)
