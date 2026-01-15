# Test-Szenarien

## Test 1: DDoS Angriff
1. Starte Simulator
2. Öffne http://localhost:5000
3. Klicke "Launch DDoS Attack"
4. Erwartetes Ergebnis:
   - 5 Wellen à 100 Requests
   - Nach Welle 2-3: Firewall-Alarm
   - Logs zeigen "RATE LIMIT EXCEEDED"
   - IP wird blockiert

## Test 2: SQL Injection
1. Klicke "Launch SQL Injection"
2. Erwartetes Ergebnis:
   - 5 verschiedene Payloads getestet
   - Mindestens 3 werden von Firewall blockiert
   - "BLOCKED BY WAF" in Logs sichtbar

## Test 3: Log-Dateien
1. Nach Angriff in `logs/` Ordner schauen
2. Datei öffnen (z.B. `DDoS_Attack_2025-11-04_15-30-45.log`)
3. Sollte vollständige Attack-Historie enthalten