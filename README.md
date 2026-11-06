# Φύλακας – λίστα απατών / Fylakas – scam feed

Υπογεγραμμένη λίστα με γνωστά ψεύτικα sites για την εφαρμογή **Φύλακας**. Ενημερώνεται μόνη της κάθε 6 ώρες.
Τα κινητά μόνο **κατεβάζουν** από εδώ· δεν ανεβαίνει τίποτα από κανέναν.

Signed list of known scam sites for the **Fylakas** app, rebuilt automatically every 6 hours.
Phones only **download** it; nothing is uploaded by anyone.

- `feed/manifest.json` + `feed/manifest.sig` (ECDSA P-256 / SHA-256; public key: `rules/feed-public-key.pem`)
- `feed/base.bin` (weekly) + `feed/delta.bin` (new since the base): sorted 5-byte SHA-256 prefixes of host names
- `feed/rules.json`, `feed/popular.txt`

Πηγές / Sources: CERT Polska warning list (hole.cert.pl), [NetAPI compromised domains](https://netapi.com/compromised-urls/) (CC BY 4.0),
Phishing.Database (MIT, archive), Tranco top-sites list, approved user reports (`rules/manual-block.txt`).

Προσφορά του Τσιμινάκη Κωνσταντίνου του Αλεξάνδρου · Offered by Konstantinos Tsiminakis, son of Alexandros
