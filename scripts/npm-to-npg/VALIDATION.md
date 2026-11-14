# Validation / Verification — 2026-11-14

## Français

Laboratoire Docker isolé, sans accès Internet : NPM 2.17.0, NPG 2.69.2, Python 3.14, Linux.

- 30 tests de régression réussis (`python3 -m unittest test_npm_to_npg.py`).
- Exécution complète en français et en anglais contre les vraies API : quatre hôtes importés, source inchangée, relance sans doublons.
- HTTP et alias, HTTPS avec validation du certificat de test, redirection avec chemin et paramètres ; `nginx -t` réussi.
- Hôte désactivé conservé désactivé et absent des configurations servies ; cas incompatibles ignorés.
- Import DDNS via la vraie API : entrée Cloudflare IPv4 désactivée, domaine distant exclu, IPv6 ignoré, relance sans doublon. Fournisseur fictif injecté dans la seule base du laboratoire.

Le certificat était une fixture locale, exposée par NPM comme un certificat Let’s Encrypt pour vérifier son téléchargement ZIP. Aucune émission ACME réelle, connexion Cloudflare réelle, activation DDNS ou bascule en production n’a été testée. Les parcours ACME et 2FA ont été simulés. Python 3.10 : syntaxe vérifiée, exécution non testée. Windows/macOS non testés. La compatibilité avec toutes les versions et configurations n’est pas garantie.

## English

Isolated Docker lab without Internet access: NPM 2.17.0, NPG 2.69.2, Python 3.14, Linux.

- 30 regression tests passed (`python3 -m unittest test_npm_to_npg.py`).
- Full French and English runs against real APIs: four hosts imported, source unchanged, no duplicates on rerun.
- HTTP and aliases, HTTPS with test-certificate verification, redirects preserving paths and query strings; `nginx -t` passed.
- Disabled host remained disabled and absent from served configurations; unsupported cases skipped.
- Real DDNS API: disabled Cloudflare IPv4 entry, remote domain excluded, IPv6 skipped, no duplicates. A dummy provider was inserted only into the lab database.

The certificate was a local fixture exposed by NPM as a Let’s Encrypt certificate to exercise ZIP downloads. Real ACME issuance, Cloudflare connections, active DDNS and production cutover were not tested. ACME and 2FA flows were simulated. Python 3.10 syntax checked, runtime not tested. Windows/macOS not tested. Compatibility with every version and configuration is not guaranteed.
