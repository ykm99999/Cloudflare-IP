import requests

def read_ips():
    with open("ip.txt", "r") as f:
        return [line.strip() for line in f if line.strip()]

def upload(ips):
    url = "https://999.f.7.6.b.0.d.0.0.1.0.a.2.ip6.arpa/api/upload"      
    payload = {
        "uuid": "7f4ca7a1-3dd6-47c5-a81f-343746e4d233",      
        "ips": ips
    }
    r = requests.post(url, json=payload)
    print("上传状态：", r.status_code, r.text)

if __name__ == "__main__":
    ip_list = read_ips()
    upload(ip_list)
