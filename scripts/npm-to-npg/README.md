# NPM → NPG

Copy hosts from Nginx Proxy Manager to Nginx Proxy Guard using an interactive script in English or French. Python 3.10+; no packages to install.

```sh
python3 npm_to_npg.py
```

Choose your language, enter server URLs and credentials, select hosts and confirm. Passwords are hidden. You can also run `python3 npm_to_npg.py --lang en`.

NPM and NPG must already be running with their accounts configured. Use temporary NPG ports if both share a machine. The script copies settings; it does not install NPG or switch ports 80/443.

- HTTP/HTTPS hosts and redirects; existing destination hosts are left unchanged.
- Certificates: reuse, copy **without automatic renewal**, or request Let’s Encrypt through DNS.
- Optional DDNS Updater import: Cloudflare IPv4 entries, always **disabled**. No DNS A/AAAA records are changed. Let’s Encrypt may create temporary TXT records.
- Hosts using ACLs, HSTS, caching, custom locations or custom Nginx configuration are reported and skipped. Streams and 404 hosts are not transferred.

NPM remains unchanged and running. Check services in NPG before cutover. Generated inventory and report files in your working directory are private: do not publish them.

Tested on Linux with NPM 2.17.0 and NPG 2.69.2. See `VALIDATION.md` for test scope.

Projects: [NPG](https://github.com/svrforum/NginxProxyGuard) · [NPM](https://github.com/NginxProxyManager/nginx-proxy-manager) · [DDNS Updater Enhanced](https://github.com/Aerya/ddns-updater-enhanced).
