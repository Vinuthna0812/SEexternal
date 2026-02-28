import requests
import csv
import subprocess
powershell_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
response = requests.get(
    "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    headers={"User-Agent": "Mozilla/5.0"},
    timeout=10
).text
rule = 'netsh advfirewall firewall delete rule name="BadIP"'
subprocess.run([powershell_path, "-Command", rule])
mycsv = csv.reader(
    filter(lambda x: not x.startswith("#"), response.splitlines())
)
for row in mycsv:
    ip = row[1]
    if ip != "dst_ip":
        print("Added Rule to block:", ip)
        rule = (
            "netsh advfirewall firewall add rule "
            "name='BadIP' Dir=Out Action=Block RemoteIP=" + ip
        )
        subprocess.run([powershell_path, "-Command", rule])