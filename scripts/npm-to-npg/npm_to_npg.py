#!/usr/bin/env python3
"""NPM → NPG interactive migrator. Python 3.10+, standard library only.
Run: python3 npm_to_npg.py   (or --lang fr / --lang en)
Source remains read-only. DNS A/AAAA records and Docker ports are never changed; ACME may create temporary TXT records.
"""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

VERSION = '1.0.0'
LANG = 'en'
MAX_BODY = 16 * 1024 * 1024


def tr(fr, en):
    return fr if LANG == 'fr' else en


class Error(Exception):
    pass


class APIError(Error):
    def __init__(self, status, path):
        self.status = status
        super().__init__(tr('Erreur HTTP', 'HTTP error') + f' {status}: {path}')


def ask(fr, en, default=''):
    suffix = f' [{default}]' if default else ''
    return input(tr(fr, en) + suffix + ': ').strip() or default


def yes(fr, en, default=False):
    while True:
        value = ask(fr, en, tr('O/n' if default else 'o/N', 'Y/n' if default else 'y/N')).lower()
        if value in ('o', 'oui', 'y', 'yes'):
            return True
        if value in ('n', 'non', 'no'):
            return False
        if value in ('o/n', 'y/n'):
            return default
        print(tr('Répondez oui ou non.', 'Please answer yes or no.'))


def select(rows, title, label, multiple=True):
    print('\n' + title)
    for i, row in enumerate(rows, 1):
        print(f'  {i}. {label(row)}')
    if not rows:
        return []
    while True:
        text = ask('Numéros séparés par des virgules, tous, ou Entrée pour aucun' if multiple else 'Numéro, ou Entrée pour passer',
                   'Comma-separated numbers, all, or Enter for none' if multiple else 'Number, or Enter to skip')
        if not text:
            return []
        if multiple and text.lower() in ('all', 'tous'):
            return list(rows)
        try:
            numbers = [int(n.strip()) for n in text.split(',')]
            if (not multiple and len(numbers) != 1) or len(set(numbers)) != len(numbers):
                raise ValueError
            if any(n < 1 or n > len(rows) for n in numbers):
                raise ValueError
            return [rows[n - 1] for n in numbers]
        except ValueError:
            print(tr('Sélection invalide.', 'Invalid selection.'))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    # Never forward a credential to a redirect target.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, url, kind, token='', verify=True, ca_file=None):
        p = urllib.parse.urlsplit(url.strip())
        if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password or p.query or p.fragment or p.path not in ('', '/'):
            raise Error(tr('Indiquez seulement http(s)://adresse:port.', 'Enter only http(s)://address:port.'))
        try:
            p.port
        except ValueError:
            raise Error(tr('Port invalide.', 'Invalid port.'))
        self.url, self.kind, self.token = url.rstrip('/'), kind, token
        context = ssl.create_default_context(cafile=ca_file) if verify else ssl._create_unverified_context()
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
        self.prefix = '/api/' if kind == 'npm' else '/api/v1/'

    def request(self, path, method='GET', payload=None, binary=False):
        if self.kind == 'npm' and method != 'GET' and path not in ('tokens', 'tokens/2fa'):
            raise Error('NPM: read-only')
        if not path or path.startswith(('/', 'http')) or '..' in path:
            raise Error('Invalid API path')
        data = None if payload is None else json.dumps(payload).encode()
        headers = {'Accept': 'application/json', 'User-Agent': f'npm-to-npg/{VERSION}'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        if data is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(self.url + self.prefix + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=45) as res:
                body = res.read(MAX_BODY + 1)
        except urllib.error.HTTPError as exc:
            # Do not print server responses: they may contain credentials.
            raise APIError(exc.code, path.split('?')[0]) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if isinstance(getattr(exc, 'reason', None), ssl.SSLCertVerificationError):
                raise Error(tr('Certificat HTTPS non reconnu. Utilisez une CA de confiance ou l’option de certificat local au démarrage.',
                               'HTTPS certificate not trusted. Use a trusted CA or the local certificate option at startup.')) from None
            raise Error(tr('Connexion impossible ou délai dépassé : ', 'Connection failed or timed out: ') + self.url) from None
        if len(body) > MAX_BODY:
            raise Error(tr('Réponse trop volumineuse.', 'Response too large.'))
        if binary:
            return body
        try:
            return json.loads(body) if body else {}
        except (ValueError, UnicodeError):
            raise Error(tr('Réponse inattendue : vérifiez l’adresse de l’interface.', 'Unexpected response: check the admin interface URL.')) from None

    def listing(self, path):
        if self.kind == 'npm':
            data = self.request(path)
            if not isinstance(data, list) or any(not isinstance(x, dict) for x in data):
                raise Error(tr('Liste NPM invalide.', 'Invalid NPM list.'))
            return [x for x in data if not flag(x.get('is_deleted'))]
        result, seen = [], set()
        for page in range(1, 101):
            data = self.request(f'{path}?page={page}&per_page=100')
            rows = data.get('data') if isinstance(data, dict) else data
            if isinstance(data, dict) and rows is None and data.get('total') == 0:
                rows = []
            if not isinstance(rows, list) or any(not isinstance(x, dict) for x in rows):
                raise Error(tr('Liste NPG invalide.', 'Invalid NPG list.'))
            for row in rows:
                key = row.get('id')
                if key is None or key in seen:
                    raise Error(tr('Pagination NPG incohérente.', 'Inconsistent NPG pagination.'))
                seen.add(key)
            result.extend(rows)
            pages = data.get('total_pages') if isinstance(data, dict) else None
            if isinstance(data, list) or not rows or (isinstance(pages, int) and page >= pages) or (pages is None and len(rows) < 100):
                return result
        raise Error(tr('Trop de pages.', 'Too many pages.'))


def flag(value):
    return value is True or value == 1 or value == '1'


def domains(row):
    data = row.get('domain_names', [])
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            data = [data]
    return [str(x).lower().strip().rstrip('.') for x in data] if isinstance(data, list) else []


def valid_domain(name):
    return len(name) <= 253 and bool(re.fullmatch(r'(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', name, re.I))


def covers(cert, names):
    def one(name):
        for pattern in domains(cert):
            if name == pattern:
                return True
            if pattern.startswith('*.') and not name.startswith('*.') and name.endswith(pattern[1:]) and name.count('.') == pattern.count('.'):
                return True
        return False
    return all(one(n) for n in names)


def usable(cert):
    if cert.get('status') != 'issued':
        return False
    expiry = cert.get('expires_at')
    if expiry:
        try:
            return dt.datetime.fromisoformat(expiry.replace('Z', '+00:00')) > dt.datetime.now(dt.timezone.utc)
        except (ValueError, TypeError):
            return False
    return False


def matching_cert(certs, names):
    matches = [c for c in certs if usable(c) and covers(c, names)]
    exact = [c for c in matches if set(domains(c)) == set(names)]
    return (exact or matches)[0] if (exact or matches) else None


def host_label(entry):
    row = entry['source']
    dest = row.get('forward_host') if entry['kind'] == 'proxy-hosts' else row.get('forward_domain_name')
    port = ':' + str(row.get('forward_port')) if entry['kind'] == 'proxy-hosts' else ''
    return ', '.join(domains(row)) + f' → {dest}{port}' + ('' if flag(row.get('enabled', True)) else tr(' (désactivé)', ' (disabled)'))


def plan_host(row, kind):
    issues = []
    names = domains(row)
    if not names or len(set(names)) != len(names) or not all(valid_domain(n) for n in names):
        issues.append(tr('nom de domaine invalide', 'invalid domain name'))
    if row.get('advanced_config', '').strip():
        issues.append(tr('configuration Nginx personnalisée', 'custom Nginx configuration'))
    for key, fr, en in [('hsts_enabled','HSTS','HSTS'), ('hsts_subdomains','HSTS sous-domaines','HSTS subdomains'), ('caching_enabled','cache NPM','NPM cache'), ('trust_forwarded_proto','confiance X-Forwarded-Proto','X-Forwarded-Proto trust')]:
        if flag(row.get(key)):
            issues.append(tr(fr, en))
    if row.get('locations') not in (None, '', '[]', []):
        issues.append(tr('emplacements personnalisés', 'custom locations'))
    if row.get('access_list_id') not in (None, 0, '0', ''):
        issues.append(tr('liste de contrôle d’accès à recréer', 'access control list must be recreated'))
    cert_id = row.get('certificate_id')
    if cert_id in (0, '0', ''):
        cert_id = None
    if flag(row.get('ssl_forced')) and not cert_id:
        issues.append(tr('HTTPS forcé sans certificat', 'forced HTTPS without certificate'))
    payload = {'domain_names': names, 'enabled': flag(row.get('enabled', True)),
               'ssl_enabled': bool(cert_id), 'ssl_force_https': bool(cert_id and flag(row.get('ssl_forced'))),
               'block_exploits': flag(row.get('block_exploits'))}
    if kind == 'proxy-hosts':
        host = str(row.get('forward_host', '')).strip()
        if host.startswith('[') and host.endswith(']'):
            host = host[1:-1]
        try:
            ipaddress.ip_address(host)
            host_valid = True
        except ValueError:
            host_valid = bool(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?', host)) and len(host) <= 253
        if not host_valid:
            issues.append(tr('destination invalide', 'invalid destination'))
        try:
            port = int(row.get('forward_port', 0))
            if not 1 <= port <= 65535 or isinstance(row.get('forward_port'), bool):
                raise ValueError
        except (ValueError, TypeError):
            port = 0
            issues.append(tr('port invalide', 'invalid port'))
        scheme = row.get('forward_scheme', 'http')
        if scheme not in ('http', 'https'):
            issues.append(tr('protocole invalide', 'invalid protocol'))
        payload.update(proxy_type='http', forward_host=host, forward_port=port, forward_scheme=scheme,
                       ssl_http2=bool(cert_id and flag(row.get('http2_support'))), ssl_http3=False,
                       allow_websocket_upgrade=flag(row.get('allow_websocket_upgrade')), cache_enabled=False, ddns_enabled=False)
    else:
        target = str(row.get('forward_domain_name', '')).strip()
        if not target or any(c in target for c in ' \t\r\n/;\\'):
            issues.append(tr('redirection invalide', 'invalid redirect'))
        try:
            code = int(row.get('forward_http_code', 301))
        except (ValueError, TypeError):
            code = 0
        scheme = row.get('forward_scheme', 'auto')
        if code not in (301, 302, 307, 308) or scheme not in ('auto', 'http', 'https'):
            issues.append(tr('redirection non prise en charge', 'unsupported redirect'))
        payload.update(forward_domain_name=target, forward_scheme=scheme, redirect_code=code, preserve_path=flag(row.get('preserve_path')))
    return {'kind': kind, 'source': row, 'payload': payload, 'issues': issues}


def inventory(npm):
    result = []
    for kind in ('proxy-hosts', 'redirection-hosts'):
        route = 'proxy-hosts' if kind == 'proxy-hosts' else 'redirect-hosts'
        result += [plan_host(row, route) for row in npm.listing('nginx/' + kind)]
    seen = {}
    for entry in result:
        for name in domains(entry['source']):
            if name in seen:
                issue = tr('domaine présent plusieurs fois', 'duplicate source domain')
                entry['issues'].append(issue)
                seen[name]['issues'].append(issue)
            seen[name] = entry
    return result


def private_json(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as out:
        json.dump(data, out, indent=2, ensure_ascii=False)
        out.write('\n')


def new_report_dir():
    import tempfile
    return Path(tempfile.mkdtemp(prefix='npm-to-npg-' + dt.datetime.now().strftime('%Y%m%d-'), dir=Path.cwd()))


def connect(kind):
    print('\n' + ('Nginx Proxy Manager (NPM)' if kind == 'npm' else 'Nginx Proxy Guard (NPG)'))
    url = ask('Adresse de l’interface, avec http:// ou https://', 'Admin URL, including http:// or https://')
    Client(url, kind)  # Validate before any credentials are requested.
    if url.startswith('http://') and not yes('Connexion HTTP non chiffrée. Est-ce un réseau privé de confiance ?', 'Unencrypted HTTP connection. Is this a trusted private network?'):
        raise Error(tr('Connexion annulée.', 'Connection cancelled.'))
    verify, ca = True, None
    if url.startswith('https://') and yes('Certificat HTTPS local ou auto-signé ?', 'Local or self-signed HTTPS certificate?'):
        ca = ask('Fichier CA PEM, ou Entrée pour accepter ce certificat sans vérification', 'CA PEM file, or Enter to accept this certificate without verification') or None
        if ca is None:
            if not yes('Sans vérification, l’identité du serveur n’est pas garantie. Continuer sur ce réseau de confiance ?', 'Without verification, server identity is not guaranteed. Continue on this trusted network?'):
                raise Error(tr('Connexion annulée.', 'Connection cancelled.'))
            verify = False
    client = Client(url, kind, verify=verify, ca_file=ca)
    if kind == 'npg' and yes('Utiliser un jeton API plutôt qu’un compte ?', 'Use an API token instead of an account?'):
        client.token = getpass.getpass(tr('Jeton API : ', 'API token: '))
    else:
        user = ask('Email NPM' if kind == 'npm' else 'Nom d’utilisateur NPG', 'NPM email' if kind == 'npm' else 'NPG username')
        password = getpass.getpass(tr('Mot de passe : ', 'Password: '))
        payload = {'identity': user, 'secret': password} if kind == 'npm' else {'username': user, 'password': password}
        response = client.request('tokens' if kind == 'npm' else 'auth/login', 'POST', payload)
        if response.get('requires_2fa') or response.get('requires_2fa_verification'):
            code = getpass.getpass(tr('Code 2FA : ', '2FA code: '))
            if kind == 'npg':
                response = client.request('auth/verify-2fa', 'POST', {'temp_token': response.get('temp_token'), 'totp_code': code})
            else:
                response = client.request('tokens/2fa', 'POST', {'challenge_token': response.get('challenge_token'), 'code': code})
        if response.get('is_initial_setup') or response.get('user', {}).get('must_change_password'):
            raise Error(tr('Terminez d’abord la création du compte dans NPG.', 'Complete NPG account setup first.'))
        client.token = response.get('token', '')
        if not client.token:
            raise Error(tr('Connexion refusée : aucun jeton reçu.', 'Login failed: no token received.'))
    return client


def compare(entry, actual):
    expected = entry['payload']
    diffs = [key for key, value in expected.items() if key not in ('domain_names',) and actual.get(key) != value]
    if set(domains(actual)) != set(expected['domain_names']):
        diffs.append('domain_names')
    return diffs


def existing_for(npg, entry):
    names = set(entry['payload']['domain_names'])
    return [r for route in ('proxy-hosts', 'redirect-hosts') for r in npg.listing(route) if names.intersection(domains(r))]


def zip_pems(data):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            selected = {}
            for base in ('fullchain', 'privkey'):
                matches = [info for info in archive.infolist() if re.fullmatch(base + r'\d*\.pem', Path(info.filename).name)]
                if len(matches) != 1 or matches[0].file_size > 2_000_000:
                    raise ValueError
                selected[base] = archive.read(matches[0]).decode('utf-8')
            return selected['fullchain'], selected['privkey']
    except (zipfile.BadZipFile, ValueError, KeyError, UnicodeError, RuntimeError):
        raise Error(tr('Archive de certificat NPM invalide ou ambiguë.', 'Invalid or ambiguous NPM certificate archive.')) from None


def validate_pem_pair(certificate, key, names):
    # Private files exist only while the standard library/OpenSSL checks the pair.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='npm-npg-cert-') as folder:
        cert_path, key_path = Path(folder) / 'cert.pem', Path(folder) / 'key.pem'
        for path, content in ((cert_path, certificate), (key_path, key)):
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write(content)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_cert_chain(str(cert_path), str(key_path), password=lambda: '')
            # CPython exposes the certificate decoder used by its own SSL tests.
            # Fail closed on Python implementations without it.
            decoded = ssl._ssl._test_decode_cert(str(cert_path))
            actual_names = [value.lower() for kind, value in decoded.get('subjectAltName', ()) if kind == 'DNS']
            if not actual_names or not covers({'domain_names': actual_names}, names):
                raise ValueError
            now = time.time()
            if ssl.cert_time_to_seconds(decoded['notAfter']) <= now or ssl.cert_time_to_seconds(decoded['notBefore']) > now:
                raise ValueError
        except (ssl.SSLError, ValueError, KeyError, AttributeError):
            raise Error(tr('Certificat invalide, expiré, domaine absent ou clé privée incompatible/chiffrée.',
                           'Invalid/expired certificate, missing domain, or mismatched/encrypted private key.')) from None


def provider_choice(npg, cloudflare_only=False):
    providers = npg.listing('dns-providers')
    if cloudflare_only:
        providers = [p for p in providers if p['provider_type'] == 'cloudflare']
    selected = select(providers, tr('Fournisseur DNS à utiliser', 'DNS provider to use'), lambda r: r['name'] + ' (' + r['provider_type'] + ')', False)
    if selected:
        return selected[0]
    if not yes('Créer une connexion Cloudflare dans NPG ?', 'Create a Cloudflare connection in NPG?'):
        return None
    print(tr('Le jeton Cloudflare doit autoriser Zone:Read et DNS:Edit pour vos zones.', 'The Cloudflare token needs Zone:Read and DNS:Edit for your zones.'))
    name = ask('Nom de la connexion', 'Connection name', 'Migration Cloudflare')
    token = getpass.getpass(tr('Jeton Cloudflare (envoyé à NPG) : ', 'Cloudflare token (sent to NPG): '))
    if not token:
        return None
    return npg.request('dns-providers', 'POST', {'name': name, 'provider_type': 'cloudflare', 'credentials': {'api_token': token}, 'is_default': False})


def resolve_certificate(npm, npg, entry, old_certs, imported, notes):
    old = entry['source'].get('certificate_id')
    if old in (None, 0, '0', ''):
        return True
    names = entry['payload']['domain_names']
    match = matching_cert(npg.listing('certificates'), names)
    if match:
        if match.get('provider') == 'custom':
            note = tr('Renouvellement manuel du certificat : ', 'Manual certificate renewal required: ') + ', '.join(domains(match))
            if note not in notes:
                notes.append(note)
        entry['payload']['certificate_id'] = match['id']
        return True
    source_cert = next((c for c in old_certs if str(c.get('id')) == str(old)), None)
    cert_names = domains(source_cert or {}) or names
    if source_cert and not covers(source_cert, names):
        raise Error(tr('Le certificat NPM déclaré ne couvre pas cet hôte.', 'The declared NPM certificate does not cover this host.'))
    print('\nHTTPS: ' + ', '.join(names))
    print(tr('1. Nouveau certificat Let’s Encrypt renouvelé par NPG\n2. Copier le certificat existant (renouvellement manuel dans NPG)\n3. Ignorer cet hôte',
             '1. New Let’s Encrypt certificate renewed by NPG\n2. Copy the existing certificate (manual renewal in NPG)\n3. Skip this host'))
    choice = ''
    while choice not in ('1', '2', '3'):
        choice = ask('Choix', 'Choice', '1')
    if choice == '1':
        provider = provider_choice(npg)
        if not provider:
            return False
        print(tr('La validation Let’s Encrypt crée des enregistrements TXT DNS temporaires.', 'Let’s Encrypt validation creates temporary DNS TXT records.'))
        if not yes('Demander ce certificat à Let’s Encrypt avec ces domaines : ' + ', '.join(cert_names) + ' ?',
                   'Request this certificate from Let’s Encrypt for: ' + ', '.join(cert_names) + '?'):
            return False
        pending = [c for c in npg.listing('certificates') if set(domains(c)) == set(cert_names) and c.get('status') in ('pending', 'issuing')]
        cert = pending[0] if pending else npg.request('certificates', 'POST', {'domain_names': cert_names, 'provider': 'letsencrypt', 'dns_provider_id': provider['id'], 'auto_renew': True, 'key_type': 'ec256'})
        cert_id = cert.get('id')
        if not cert_id:
            raise Error(tr('Réponse de certificat sans identifiant.', 'Certificate response has no ID.'))
        print(tr('Émission en cours (jusqu’à 5 minutes)…', 'Issuing certificate (up to 5 minutes)…'))
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            cert = npg.request('certificates/' + str(cert_id))
            if usable(cert):
                break
            if cert.get('status') in ('error', 'failed'):
                raise Error(tr('Émission refusée. Consultez le certificat dans NPG.', 'Issuance failed. Check the certificate in NPG.'))
            time.sleep(3)
        else:
            raise Error(tr('Certificat toujours en attente. Relancez après son émission dans NPG.', 'Certificate still pending. Rerun once issued in NPG.'))
    elif choice == '2':
        if not yes('Copier le certificat ET sa clé privée de NPM vers NPG, sans renouvellement automatique ?',
                   'Copy the certificate AND its private key from NPM to NPG, without automatic renewal?'):
            return False
        if source_cert and source_cert.get('provider') == 'letsencrypt':
            certificate, key = zip_pems(npm.request(f'nginx/certificates/{old}/download', binary=True))
        else:
            print(tr('NPM ne fournit pas la clé des certificats personnalisés par API.', 'NPM does not expose custom certificate keys through its API.'))
            certificate = Path(ask('Fichier du certificat PEM/fullchain', 'Certificate PEM/fullchain file')).expanduser().read_text()
            key = Path(ask('Fichier de la clé privée PEM', 'Private key PEM file')).expanduser().read_text()
        validate_pem_pair(certificate, key, cert_names)
        cert = npg.request('certificates/upload', 'POST', {'domain_names': cert_names, 'certificate_pem': certificate, 'private_key_pem': key})
        notes.append(tr('Renouvellement manuel du certificat : ', 'Manual certificate renewal required: ') + ', '.join(cert_names))
    else:
        return False
    if cert.get('id'):
        imported.append({'kind': 'certificates', 'id': cert['id']})
    if not usable(cert) or not covers(cert, names):
        raise Error(tr('Le certificat ne couvre pas cet hôte ou est expiré.', 'The certificate is expired or does not cover this host.'))
    entry['payload']['certificate_id'] = cert['id']
    return True


def import_entry(npg, entry):
    # Recheck directly before each write: a rerun never overwrites an existing host.
    existing = existing_for(npg, entry)
    if existing:
        return {'result': 'exists', 'domains': entry['payload']['domain_names'], 'differences': compare(entry, existing[0]) if len(existing) == 1 else ['multiple hosts']}
    obj = npg.request(entry['kind'], 'POST', entry['payload'])
    if not isinstance(obj, dict) or not obj.get('id'):
        raise Error(tr('Réponse d’import inattendue. Vérifiez NPG avant de relancer.', 'Unexpected import response. Check NPG before rerunning.'))
    actual = npg.request(entry['kind'] + '/' + str(obj['id']))
    diffs = compare(entry, actual)
    return {'result': 'different' if diffs else 'created', 'kind': entry['kind'], 'id': obj['id'], 'domains': entry['payload']['domain_names'], 'differences': diffs}


def prepare_ddns(npg, records):
    # DDNS entries are ALWAYS created disabled. DDNS never changes DNS A/AAAA records in this tool.
    existing = {r['hostname'].lower() for r in npg.listing('ddns-records')}
    result = []
    for row in records:
        name = str(row.get('domain', '')).lower().strip().rstrip('.')
        if row.get('provider') != 'cloudflare' or not valid_domain(name) or name.startswith('*.') or name in existing:
            continue
        if row.get('ip_version') != 'ipv4':
            result.append({'domain': name, 'result': 'skipped', 'reason': tr('version IP non explicitement IPv4', 'IP version not explicitly IPv4')})
            continue
        if not yes('DDNS : ' + name + ' doit-il suivre l’IP publique de CE serveur NPG (et non un serveur externe) ?',
                   'DDNS: should ' + name + ' follow THIS NPG server’s public IP (not a remote server)?'):
            continue
        provider = provider_choice(npg, cloudflare_only=True)
        if not provider:
            continue
        proxied = row.get('proxied', False)
        ttl = row.get('ttl', 1)
        if not isinstance(proxied, bool) or not isinstance(ttl, int) or (ttl != 1 and not 60 <= ttl <= 86400):
            raise Error(tr('TTL/proxy DDNS invalide.', 'Invalid DDNS TTL/proxy value.'))
        if not yes('Créer cette entrée DDNS désactivée ?', 'Create this disabled DDNS entry?'):
            continue
        obj = npg.request('ddns-records', 'POST', {'hostname': name, 'dns_provider_id': provider['id'], 'proxied': proxied, 'ttl': ttl, 'enabled': False})
        check = npg.request('ddns-records/' + str(obj['id']))
        if check.get('enabled') is not False:
            raise Error(tr('État DDNS inattendu : vérifiez NPG immédiatement.', 'Unexpected DDNS state: check NPG immediately.'))
        existing.add(name)
        result.append({'domain': name, 'result': 'created-disabled', 'id': obj['id']})
    return result


def run():
    print(f'\nNPM → NPG {VERSION}')
    print(tr('Copie des hôtes sélectionnés. NPM, DNS A/AAAA et ports Docker restent inchangés.',
             'Copies selected hosts. NPM, DNS A/AAAA records and Docker ports remain unchanged.'))
    npm = connect('npm')
    entries = inventory(npm)
    old_certs = npm.listing('nginx/certificates')
    for resource in ('streams', 'dead-hosts'):
        rows = npm.listing('nginx/' + resource)
        if rows:
            print(tr('Non transférés : ', 'Not transferred: ') + f'{len(rows)} {resource}')
    npg = connect('npg')
    existing = npg.listing('proxy-hosts') + npg.listing('redirect-hosts')
    existing_names = {n for r in existing for n in domains(r)}
    candidates, skipped = [], []
    for entry in entries:
        if entry['issues']:
            skipped.append({'domains': domains(entry['source']), 'reason': '; '.join(entry['issues'])})
        elif existing_names.intersection(domains(entry['source'])):
            skipped.append({'domains': domains(entry['source']), 'reason': tr('déjà présent : conservé sans modification', 'already present: left unchanged')})
        else:
            candidates.append(entry)
    for item in skipped:
        print(tr('Ignoré : ', 'Skipped: ') + ', '.join(item['domains']) + ' — ' + item['reason'])
    selected = select(candidates, tr('Quels hôtes doivent passer par cette instance NPG ?\nNe sélectionnez pas les anciens hôtes déplacés sur un autre serveur.',
                                    'Which hosts should be served through this NPG instance?\nDo not select obsolete hosts moved to another server.'), host_label)
    if not selected:
        print(tr('Aucun hôte sélectionné. Rien n’a été modifié.', 'No hosts selected. Nothing was changed.'))
        return 0
    print('\n' + tr('À importer :', 'To import:'))
    for entry in selected:
        print('  ' + host_label(entry))
    print(tr('Les certificats HTTPS manquants seront proposés séparément. Le DDNS restera désactivé.',
             'Missing HTTPS certificates will be handled separately. DDNS will stay disabled.'))
    if not yes('Lancer la copie de ces hôtes vers NPG ?', 'Start copying these hosts to NPG?'):
        print(tr('Annulé. Aucun changement.', 'Cancelled. No changes.'))
        return 0
    folder = new_report_dir()
    private_json(folder / 'npm-inventory.json', {'entries': entries, 'certificates': old_certs})
    private_json(folder / 'npg-hosts-before.json', existing)
    print(tr('Inventaire privé et rapport : ', 'Private inventory and report: ') + str(folder))
    report = {'version': VERSION, 'results': [], 'skipped': skipped, 'created_certificates': [], 'notes': [], 'ddns': []}
    failed = False
    try:
        for entry in selected:
            try:
                if existing_for(npg, entry):
                    report['results'].append({'result': 'exists', 'domains': domains(entry['source'])})
                    continue
                if not resolve_certificate(npm, npg, entry, old_certs, report['created_certificates'], report['notes']):
                    report['results'].append({'result': 'skipped', 'domains': domains(entry['source'])})
                    continue
                outcome = import_entry(npg, entry)
                report['results'].append(outcome)
                labels = {'created': tr('IMPORTÉ', 'IMPORTED'), 'exists': tr('DÉJÀ PRÉSENT', 'ALREADY EXISTS'), 'different': tr('À VÉRIFIER', 'CHECK REQUIRED')}
                print(labels[outcome['result']] + ': ' + ', '.join(outcome['domains']))
                if outcome['result'] == 'different':
                    failed = True
                    print(tr('Différences : ', 'Differences: ') + ', '.join(outcome['differences']))
            except (Error, OSError) as exc:
                failed = True
                report['results'].append({'result': 'error', 'domains': domains(entry['source']), 'error': str(exc)})
                print(tr('Échec : ', 'Failed: ') + str(exc))
                if not yes('Continuer avec les hôtes suivants ?', 'Continue with the remaining hosts?'):
                    break
        if yes('Préparer aussi le DDNS Cloudflare depuis un fichier DDNS Updater ?', 'Also prepare Cloudflare DDNS from a DDNS Updater file?'):
            print(tr('Les entrées seront désactivées. Activez-les dans NPG seulement après la bascule et l’arrêt de l’ancien actualiseur.',
                     'Entries will be disabled. Enable them in NPG only after cutover and stopping the old updater.'))
            path = Path(ask('Chemin du fichier config.json', 'Path to config.json')).expanduser()
            data = json.loads(path.read_text())
            rows = data.get('settings') if isinstance(data, dict) else None
            if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
                raise Error(tr('Fichier DDNS Updater invalide.', 'Invalid DDNS Updater file.'))
            report['ddns'] = prepare_ddns(npg, rows)
    finally:
        private_json(folder / 'report.json', report)
    for note in report['notes']:
        print(note)
    created = sum(r['result'] == 'created' for r in report['results'])
    print(tr(f'\n{created} hôte(s) importé(s) et configuration relue.', f'\n{created} host(s) imported and configuration checked.'))
    print(tr('NPM reste actif. Testez NPG sur ses ports provisoires avant de lui attribuer 80/443.\nAucun DNS A/AAAA, routeur ou réglage AdGuard modifié.',
             'NPM remains active. Test NPG on its temporary ports before assigning 80/443 to it.\nNo DNS A/AAAA records, router or AdGuard settings were changed.'))
    print(tr('Rapport : ', 'Report: ') + str(folder / 'report.json'))
    return 2 if failed else 0


def main(argv=None):
    global LANG
    parser = argparse.ArgumentParser(description='NPM → NPG / Français & English / Python 3.10+')
    parser.add_argument('--lang', choices=['fr', 'en'])
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args(argv)
    LANG = args.lang or input('Language / Langue [fr/en]: ').strip().lower()
    if LANG not in ('fr', 'en'):
        LANG = 'en'
    try:
        return run()
    except (KeyboardInterrupt, EOFError):
        print('\n' + tr('Arrêt demandé. Les éléments déjà copiés sont conservés ; relancer ne les écrase pas.',
                         'Stopped. Items already copied are kept; rerunning does not overwrite them.'))
        return 130
    except (Error, OSError, ValueError) as exc:
        print(tr('Erreur : ', 'Error: ') + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
