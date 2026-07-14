import asyncio, tempfile, unittest, json
from pathlib import Path
from outrider import mcp_enrichment as e
from outrider.approval import grant_approval
from outrider.state import initialize_state, transition_state

class Fake:
    def __init__(self): self.calls=[]
    async def invoke(self, tool,args): self.calls.append((tool,args)); return [{"ok": True}]

def run(c): return asyncio.run(c)

def make_run(tmp, target='example.com'):
    d=Path(tmp)/'run'; d.mkdir(); (d/'scope.yaml').write_text('in_scope:\n  - "example.com"\n  - "*.example.com"\nout_of_scope: []\n')
    initialize_state(d,target,'authorized-operator','ROE'); return d

class MCPEnrichmentTests(unittest.TestCase):
    def test_catalog_fixed(self):
        cat=e.catalog(True); names=[x['tool_name'] for x in cat]
        self.assertEqual(names, sorted(['crtsh_lookup','hudsonrock_lookup','epss_score','wayback_urls','dns_records']))
        self.assertEqual(len(cat),5); self.assertFalse(any('://' in json.dumps(x) for x in cat))
        dns=next(x for x in cat if x['tool_name']=='dns_records'); self.assertTrue(dns['approval_required']); self.assertEqual(dns['action_type'],'target_enumeration')
        epss=next(x for x in cat if x['tool_name']=='epss_score'); self.assertEqual(epss['candidate_source'],'manifest_target')
    def test_argument_validation(self):
        self.assertEqual(e.validate_arguments('crtsh_lookup', {'domain':'EXAMPLE.com.'}, web=True)['domain'], 'example.com')
        for bad in ['https://example.com','example.com/path','a:b','*.example.com','127.0.0.1','bad']:
            with self.assertRaises(Exception): e.validate_arguments('crtsh_lookup', {'domain':bad}, web=True)
        self.assertEqual(e.validate_arguments('epss_score', {'cve_id':'cve-2026-12345'}, web=True)['cve_id'], 'CVE-2026-12345')
        self.assertEqual(e.validate_arguments('wayback_urls', {'domain':'example.com','limit':1}, web=True)['limit'],1)
        self.assertEqual(e.validate_arguments('wayback_urls', {'domain':'example.com','limit':500}, web=True)['limit'],500)
        for bad in [0,-1,501,'1',1.2,True]:
            with self.assertRaises(Exception): e.validate_arguments('wayback_urls', {'domain':'example.com','limit':bad}, web=True)
        with self.assertRaises(Exception): e.validate_arguments('epss_score', {'cve_id':'bad'}, web=True)
        with self.assertRaises(Exception): e.validate_arguments('epss_score', {'cve_id':'CVE-2026-1234','domain':'example.com'}, web=True)
    def test_policy_before_transport_and_dns_approval(self):
        with tempfile.TemporaryDirectory() as td:
            r=make_run(td); f=Fake(); pol,res=run(e.invoke(str(r),'crtsh_lookup',{'domain':'example.com'},f,web=True))
            self.assertEqual(pol.decision,'deny'); self.assertEqual(f.calls,[])
            transition_state(r,'scoped','authorized-operator')
            pol,res=run(e.invoke(str(r),'crtsh_lookup',{'domain':'example.com'},f,web=True)); self.assertEqual(pol.decision,'allow'); self.assertEqual(len(f.calls),1)
            pol,res=run(e.invoke(str(r),'dns_records',{'domain':'api.example.com'},f,web=True)); self.assertEqual(pol.decision,'deny'); self.assertEqual(len(f.calls),1)
            grant_approval(r,'target_enumeration','api.example.com','authorized-operator','ok',duration_minutes=30)
            pol,res=run(e.invoke(str(r),'dns_records',{'domain':'api.example.com'},f,web=True)); self.assertEqual(pol.decision,'allow'); self.assertEqual(len(f.calls),2)
