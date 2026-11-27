import httpx

SERVER = "https://vexr-lab-c2-academic-production.up.railway.app"
TOKEN = "8822853055:AAFOBse3383qi31m7fPiNmhczzr8JAuclak"
ALLOWED_CHAT_ID = ""
sudo = ""

def ask_server(endpoint):
    r = httpx.get(f"{SERVER}/api/devices", timeout=10)
    if r.status_code != 200:
        raise ConnectionError("سرور زنده نیست")
    else:
        print("everyting is good")

if __name__ == "__main__":
    ask_server(SERVER)
    