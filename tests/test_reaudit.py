import unittest,json,tempfile,subprocess,sys
from pathlib import Path
from firewalld_zone_audit import analyze
from firewalld_zone_audit.common import InputError
PROJECT=Path(__file__).resolve().parents[1]
class ReauditTests(unittest.TestCase):
    def good(self):return json.loads((PROJECT/'examples/good.json').read_text())
    def cli(self,snapshot,expected):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'case.json';p.write_text(json.dumps(snapshot))
            r=subprocess.run([sys.executable,'-m','firewalld_zone_audit',str(p)],capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,expected,r.stderr)
            self.assertNotIn('Traceback',r.stderr)
            return json.loads(r.stdout)
    def test_text_only_elements_cannot_hide_native_semantics(self):
        for inner in ('<short><forward/></short>','<description><service name="ssh"/></description>','<short unknown="x">text</short>'):
            s=self.good();s['zones']['public']=s['zones']['public'].replace('</zone>',inner+'</zone>')
            with self.assertRaises(InputError):analyze(s)
            self.assertEqual(self.cli(s,2)['status'],'ERROR')
    def test_referenced_service_description_children_rejected(self):
        s=self.good();s['zones']['public']=s['zones']['public'].replace('</zone>','<service name="web"/></zone>');s['services']={'web':'<service><description><port port="443" protocol="tcp"/></description></service>'}
        with self.assertRaises(InputError):analyze(s)
    def test_plain_text_description_keeps_valid_closed_zone(self):
        s=self.good();s['zones']['public']=s['zones']['public'].replace('</zone>','<description>Plain &amp; safe text</description></zone>')
        self.assertEqual(analyze(s)['status'],'PASS');self.assertEqual(self.cli(s,0)['status'],'PASS')
