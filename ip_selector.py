# 模拟生成优选 IP 并保存到 ip.txt
ips = [
    "1.1.1.1",
    "1.0.0.1",
    "104.16.132.229",
    "104.17.175.85",
    "162.159.192.1"
]

with open("ip.txt", "w") as f:
    for ip in ips:
        f.write(ip + "\n")
