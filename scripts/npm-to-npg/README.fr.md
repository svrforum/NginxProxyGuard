# NPM → NPG

Copiez vos hôtes de Nginx Proxy Manager vers Nginx Proxy Guard avec un script interactif, en français ou en anglais. Python 3.10+ ; aucun module à installer.

```sh
python3 npm_to_npg.py
```

Choisissez la langue, renseignez les adresses et les comptes, sélectionnez les hôtes puis confirmez. Les mots de passe ne s’affichent pas. Vous pouvez aussi lancer `python3 npm_to_npg.py --lang fr`.

NPM et NPG doivent déjà fonctionner et leurs comptes être configurés. S’ils partagent une machine, utilisez des ports provisoires pour NPG. Le script copie les réglages ; il n’installe pas NPG et ne bascule pas les ports 80/443.

- Hôtes HTTP/HTTPS et redirections ; les hôtes déjà présents restent inchangés.
- Certificats : réutilisation, copie **sans renouvellement automatique**, ou demande Let’s Encrypt par DNS.
- Option DDNS Updater : import des entrées Cloudflare IPv4, **désactivées**. Aucun enregistrement DNS A/AAAA n’est changé. Let’s Encrypt peut créer des TXT temporaires.
- Les hôtes avec ACL, HSTS, cache, emplacements ou configuration Nginx personnalisés sont signalés et ignorés. Les streams et hôtes 404 ne sont pas transférés.

NPM reste intact et actif. Vérifiez les services dans NPG avant la bascule. L’inventaire et le rapport créés dans le répertoire courant sont privés : ne les publiez pas.

Tests : NPM 2.17.0 et NPG 2.69.2 sous Linux. Voir `VALIDATION.md` pour le périmètre vérifié.

Projets : [NPG](https://github.com/svrforum/NginxProxyGuard) · [NPM](https://github.com/NginxProxyManager/nginx-proxy-manager) · [DDNS Updater Enhanced](https://github.com/Aerya/ddns-updater-enhanced).
