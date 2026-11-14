"""Offline regression tests: python3 -m unittest -v test_npm_to_npg.py"""
import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import npm_to_npg as m


def host(**changes):
    row = dict(id=1, domain_names=['app.example.test'], forward_host='backend', forward_port=80,
               forward_scheme='http', certificate_id=0, enabled=True, access_list_id=0,
               locations=[], advanced_config='', block_exploits=True)
    row.update(changes)
    return row


class Plans(unittest.TestCase):
    def setUp(self):
        m.LANG = 'en'

    def test_http_and_disabled_preserved_no_ddns(self):
        e = m.plan_host(host(enabled=False, allow_websocket_upgrade=True), 'proxy-hosts')
        self.assertEqual(e['issues'], [])
        self.assertFalse(e['payload']['enabled'])
        self.assertFalse(e['payload']['ddns_enabled'])
        self.assertTrue(e['payload']['allow_websocket_upgrade'])
        self.assertTrue(e['payload']['block_exploits'])

    def test_security_settings_never_silently_dropped(self):
        for change in [dict(access_list_id=2), dict(advanced_config='deny all;'), dict(locations=[{'path':'/private'}]),
                       dict(hsts_enabled=True), dict(hsts_subdomains=True), dict(caching_enabled=True),
                       dict(trust_forwarded_proto=True), dict(ssl_forced=True)]:
            with self.subTest(change=change):
                self.assertTrue(m.plan_host(host(**change), 'proxy-hosts')['issues'])

    def test_https_mapping(self):
        e=m.plan_host(host(certificate_id=9, ssl_forced=True, http2_support=True), 'proxy-hosts')
        self.assertTrue(e['payload']['ssl_enabled'])
        self.assertTrue(e['payload']['ssl_force_https'])
        self.assertTrue(e['payload']['ssl_http2'])
        self.assertNotIn('certificate_id', e['payload']) # Old NPM integer must not be reused as NPG UUID.

    def test_string_zero_certificate(self):
        e=m.plan_host(host(certificate_id='0'), 'proxy-hosts')
        self.assertFalse(e['payload']['ssl_enabled'])

    def test_redirect_path_and_code(self):
        e=m.plan_host(dict(domain_names=['old.example.test'],forward_domain_name='new.example.test',
                           forward_scheme='https',forward_http_code=308,preserve_path=True), 'redirect-hosts')
        self.assertFalse(e['issues'])
        self.assertTrue(e['payload']['preserve_path'])
        self.assertEqual(e['payload']['redirect_code'],308)

    def test_invalid_input_never_ready(self):
        for change in [dict(domain_names=['bad;name.test']),dict(forward_host='x; include /etc/passwd;'),
                       dict(forward_port=0),dict(forward_port=True),dict(forward_port=65536),dict(forward_scheme='ftp')]:
            with self.subTest(change=change):
                self.assertTrue(m.plan_host(host(**change),'proxy-hosts')['issues'])

    def test_ipv6_backend(self):
        e=m.plan_host(host(forward_host='[2001:db8::1]'),'proxy-hosts')
        self.assertFalse(e['issues'])
        self.assertEqual(e['payload']['forward_host'],'2001:db8::1')

    def test_duplicate_source_domains_both_flagged(self):
        class Source:
            def listing(self,path):
                return [host(),host(id=2)] if path.endswith('proxy-hosts') else []
        entries=m.inventory(Source())
        self.assertTrue(all(e['issues'] for e in entries))

    def test_missing_response_fields_are_differences(self):
        e=m.plan_host(host(),'proxy-hosts')
        actual=dict(e['payload']);actual.pop('block_exploits')
        self.assertIn('block_exploits',m.compare(e,actual))

    def test_extra_domains_are_differences(self):
        e=m.plan_host(host(),'proxy-hosts');actual=dict(e['payload'],domain_names=['app.example.test','extra.example.test'])
        self.assertIn('domain_names',m.compare(e,actual))


class Certificates(unittest.TestCase):
    def test_wildcard_exactly_one_level(self):
        c={'domain_names':['*.example.test']}
        self.assertTrue(m.covers(c,['app.example.test']))
        self.assertFalse(m.covers(c,['example.test']))
        self.assertFalse(m.covers(c,['deep.app.example.test']))

    def test_expired_pending_and_missing_expiry_rejected(self):
        for cert in [{'status':'pending'},{'status':'issued'},{'status':'issued','expires_at':'2020-01-01T00:00:00Z'}]:
            self.assertFalse(m.usable(cert))

    def test_exact_certificate_preferred(self):
        date=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=5)).isoformat()
        wildcard=dict(id='wild',status='issued',expires_at=date,domain_names=['*.example.test'])
        exact=dict(id='exact',status='issued',expires_at=date,domain_names=['app.example.test'])
        self.assertEqual(m.matching_cert([wildcard,exact],['app.example.test'])['id'],'exact')

    def test_npm_numbered_pem_zip(self):
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z:
            z.writestr('fullchain12.pem','cert');z.writestr('privkey12.pem','key')
        self.assertEqual(m.zip_pems(buf.getvalue()),('cert','key'))

    def test_zip_ambiguity_and_missing_key_rejected(self):
        for files in [('fullchain.pem',),('fullchain.pem','fullchain2.pem','privkey.pem')]:
            buf=io.BytesIO()
            with zipfile.ZipFile(buf,'w') as z:
                for f in files:z.writestr(f,'contents')
            with self.assertRaises(m.Error):m.zip_pems(buf.getvalue())

    def test_invalid_pair_rejected_without_upload(self):
        with self.assertRaises(m.Error):m.validate_pem_pair('not a cert','not a key',['app.example.test'])

    def test_le_failure_never_imports_a_host(self):
        e=m.plan_host(host(certificate_id=1),'proxy-hosts')
        old=[{'id':1,'domain_names':['app.example.test'],'provider':'letsencrypt'}]
        class API:
            def __init__(self):self.posts=[]
            def listing(self,path):return []
            def request(self,path,method='GET',payload=None):
                if method=='POST':self.posts.append(path);return {'id':'pending'}
                return {'id':'pending','status':'failed'}
        api=API()
        with patch('builtins.input',return_value='1'),patch.object(m,'yes',return_value=True),patch.object(m,'provider_choice',return_value={'id':'provider'}):
            with self.assertRaises(m.Error):m.resolve_certificate(None,api,e,old,[],[])
        self.assertEqual(api.posts,['certificates'])
        self.assertNotIn('certificate_id',e['payload'])

    def test_le_reuses_pending_request(self):
        e=m.plan_host(host(certificate_id=1),'proxy-hosts');old=[{'id':1,'domain_names':['app.example.test']}]
        date=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=5)).isoformat()
        class API:
            def listing(self,path):return [{'id':'pending','domain_names':['app.example.test'],'status':'pending'}]
            def request(self,path,method='GET',payload=None):
                assert method=='GET'
                return {'id':'pending','domain_names':['app.example.test'],'status':'issued','expires_at':date}
        with patch('builtins.input',return_value='1'),patch.object(m,'yes',return_value=True),patch.object(m,'provider_choice',return_value={'id':'provider'}):
            self.assertTrue(m.resolve_certificate(None,API(),e,old,[],[]))
        self.assertEqual(e['payload']['certificate_id'],'pending')


class API(unittest.TestCase):
    def test_null_empty_list(self):
        c=m.Client('https://example.test','npg')
        with patch.object(c,'request',return_value={'data':None,'total':0,'total_pages':0}):
            self.assertEqual(c.listing('redirect-hosts'),[])

    def test_null_nonempty_rejected(self):
        c=m.Client('https://example.test','npg')
        with patch.object(c,'request',return_value={'data':None,'total':3}):
            with self.assertRaises(m.Error):c.listing('proxy-hosts')

    def test_pagination(self):
        c=m.Client('https://example.test','npg')
        responses=[{'data':[{'id':'1'}],'total_pages':2},{'data':[{'id':'2'}],'total_pages':2}]
        with patch.object(c,'request',side_effect=responses):
            self.assertEqual(len(c.listing('proxy-hosts')),2)

    def test_duplicate_pages_rejected(self):
        c=m.Client('https://example.test','npg')
        with patch.object(c,'request',return_value={'data':[{'id':'1'}],'total_pages':2}):
            with self.assertRaises(m.Error):c.listing('proxy-hosts')

    def test_source_writes_blocked(self):
        c=m.Client('https://example.test','npm')
        with self.assertRaises(m.Error):c.request('nginx/proxy-hosts','POST',{})
        with self.assertRaises(m.Error):c.request('nginx/proxy-hosts/1','DELETE')

    def test_redirect_cannot_forward_credentials(self):
        self.assertIsNone(m.NoRedirect().redirect_request(None,None,302,'',{},'https://elsewhere.example.test'))

    def test_bad_urls_rejected(self):
        for u in ['https://user:pass@example.com','https://example.test/path','https://example.test?token=x','ftp://example.test','https://example.test:99999']:
            with self.subTest(url=u),self.assertRaises(m.Error):m.Client(u,'npg')

    def test_npm_and_npg_2fa_payloads(self):
        for lang,kind,path,field in [('en','npm','tokens/2fa','code'),('fr','npg','auth/verify-2fa','totp_code')]:
            m.LANG=lang
            responses=[{'requires_2fa':True,'challenge_token':'npm-challenge','temp_token':'npg-challenge'},{'token':'session-token'}]
            with patch.object(m,'ask',side_effect=['https://example.test','test-user']),patch.object(m,'yes',return_value=False),patch('getpass.getpass',side_effect=['test-password','123456']),patch.object(m.Client,'request',side_effect=responses) as request:
                c=m.connect(kind)
            self.assertEqual(c.token,'session-token')
            self.assertEqual(request.call_args.args[0],path)
            self.assertEqual(request.call_args.args[2][field],'123456')


class Interaction(unittest.TestCase):
    def test_fr_en_defaults_and_answers(self):
        for lang in ['fr','en']:
            m.LANG=lang
            with patch('builtins.input',return_value=''):
                self.assertFalse(m.yes('Test','Test'))
                self.assertTrue(m.yes('Test','Test',True))
            with patch('builtins.input',side_effect=['bad','oui']):
                self.assertTrue(m.yes('Test','Test'))

    def test_empty_selection_and_invalid_numbers(self):
        with patch('builtins.input',return_value=''):
            self.assertEqual(m.select([1,2],'test',str),[])
        with patch('builtins.input',side_effect=['0','3','1,1','1,2']):
            self.assertEqual(m.select([1,2],'test',str),[1,2])

    def test_private_report_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'report.json';m.private_json(p,{'safe':True})
            self.assertEqual(p.stat().st_mode & 0o777,0o600)
            with self.assertRaises(FileExistsError):m.private_json(p,{})

    def test_existing_host_never_overwritten(self):
        class API:
            def listing(self,path):return [dict(host(),id='existing')] if path=='proxy-hosts' else []
            def request(self,*args):raise AssertionError('Unexpected write')
        result=m.import_entry(API(),m.plan_host(host(),'proxy-hosts'))
        self.assertEqual(result['result'],'exists')


if __name__ == '__main__':
    unittest.main()
