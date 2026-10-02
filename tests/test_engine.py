import unittest
from firewalld_zone_audit import analyze
from firewalld_zone_audit.common import InputError

class FireTests(unittest.TestCase):
    def good(self):return {'zones':{'public':'<zone target="DROP"><interface name="eth0"/></zone>'},'active_zones':['public']}
    def test_explicit_closed_zone(self):self.assertEqual(analyze(self.good())['status'],'PASS')
    def test_accept_target(self):
        s=self.good();s['zones']['public']=s['zones']['public'].replace('DROP','ACCEPT');self.assertEqual(analyze(s)['status'],'FAIL')
    def test_implicit_target(self):self.assertEqual(analyze({'zones':{'z':'<zone/>'}})['status'],'OPEN')
    def test_missing_service(self):
        s=self.good();s['zones']['public']='<zone target="DROP"><service name="web"/></zone>';self.assertEqual(analyze(s)['status'],'OPEN')
    def test_service_exposure(self):
        s=self.good();s['zones']['public']='<zone target="DROP"><interface name="eth0"/><service name="web"/></zone>';s['services']={'web':'<service><port port="443" protocol="tcp"/></service>'};self.assertEqual(analyze(s)['status'],'OPEN')
    def test_wide_range(self):
        s=self.good();s['zones']['public']='<zone target="DROP"><port port="1-65535" protocol="tcp"/></zone>';self.assertEqual(analyze(s)['status'],'FAIL')
    def test_invalid_range(self):
        with self.assertRaises(InputError):analyze({'zones':{'z':'<zone><port port="100-1" protocol="tcp"/></zone>'}})
    def test_entity_rejected(self):
        with self.assertRaises(InputError):analyze({'zones':{'z':'<!DOCTYPE zone [<!ENTITY x "x">]><zone>&x;</zone>'}})
    def test_xml_depth(self):
        with self.assertRaises(InputError):analyze({'zones':{'z':'<zone>'+'<x>'*34+'</x>'*34+'</zone>'}})
    def test_leaf_cannot_hide_elements(self):
        with self.assertRaises(InputError):analyze({'zones':{'z':'<zone target="DROP"><interface name="eth0"><service name="web"/></interface></zone>'}})
    def test_rich_rule_open(self):
        s=self.good();s['zones']['public']=s['zones']['public'].replace('</zone>','<rule><accept/></rule></zone>');self.assertEqual(analyze(s)['status'],'OPEN')
