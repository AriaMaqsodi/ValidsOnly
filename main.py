import base64
import os
import signal
import threading
import httpx
import subprocess
from xray_url_decoder.XrayUrlDecoder import XrayUrlDecoder


xray_config_template = """{
  "log": {
    "access": "",
    "error": "",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "socks",
      "port": 10508,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ],
        "routeOnly": false
      },
      "settings": {
        "auth": "noauth",
        "udp": true,
        "allowTransparent": false
      }
    },
    {
      "tag": "http",
      "port": 10509,
      "listen": "127.0.0.1",
      "protocol": "http",
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ],
        "routeOnly": false
      },
      "settings": {
        "auth": "noauth",
        "udp": true,
        "allowTransparent": false
      }
    }
  ],
  "outbounds": [%s]
}"""


def run_subprocess(config: str):
    global process
    process = subprocess.Popen(
        ["./xray"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    process.communicate(config.encode())


plist = httpx.get(
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/channels/security/tls"
).text
plist = base64.b64decode(plist)

results = dict()
for item in plist.splitlines():
    decoded_url = XrayUrlDecoder(item.decode())
    stream_settings = decoded_url.stream_setting_obj()
    if hasattr(stream_settings, 'tlsSettings') and hasattr(stream_settings.tlsSettings, 'serverName'):
        sni = stream_settings.tlsSettings.serverName.lower().rstrip('.')
        if sni.endswith(".workers.dev") or sni.endswith(".pages.dev"):
            continue
    expose_local = xray_config_template % (decoded_url.generate_json_str())

    thread = threading.Thread(target=run_subprocess, args=(expose_local,))
    thread.start()

    if not thread.is_alive():
        print("Thread is not alive!")
        continue

    try:
        data = httpx.get(
            "https://open.spotify.com/", proxy="http://127.0.0.1:10509"
        )
        if data.status_code == 200:
            total_sec = data.elapsed.total_seconds()
            results[decoded_url.name] = {"link": decoded_url.link, "response_time": total_sec}
            print(f"Get request completed in {total_sec} with:\n{item.decode()}")

    except Exception as e:
        print("Error:")
        print(e)
        continue

    finally:
        if process.poll() is None:
            os.kill(process.pid, signal.SIGTERM)

with open("results.txt", "w", encoding="utf-8") as f:
    for _, value in sorted(results.items(), key=lambda item: item[1]["response_time"]):
        f.write(f"{value['link']}\n")
