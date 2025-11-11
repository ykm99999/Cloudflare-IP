import requests

def read_ips():
    try:
        with open("ip.txt", "r") as f:  
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("ip.txt 文件未找到，跳过上传")
        return []

def upload(ips):
    if not ips:
        print("没有可上传的 IP")
        return

    url = "https://999.f.7.6.b.0.d.0.0.1.0.a.2.ip6.arpa/api/upload"
    payload = {
        "uuid": "7f4ca7a1-3dd6-47c5-a81f-343746e4d233",
        "ips": ips
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        print("上传状态：", response.status_code)
        print("返回内容：", response.text)
    except requests.exceptions.RequestException as e:
        print("上传失败：", e)

if __name__ == "__main__":
    ip_list = read_ips()
    upload(ip_list)
