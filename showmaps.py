import sys,json;
rules=json.loads(sys.stdin.read())
for rule in rules:
    ip_version = "ipv4"  if len(rule['key'])== 4 else "ipv6"
    if ip_version=="ipv6":
        chunks_k = [rule['key'][idx: idx+2] for idx in range(0,len(rule['key']),2)]
        k = ':'.join( reversed([f"{chunk[1]}{chunk[0]}".replace("0x","") for chunk in chunks_k]))
    elif ip_version=="ipv4":
         k = '.'.join( reversed([str(int(k.replace("0x",""),16)) for k in rule['key']]))
    else:
        raise ValueError("wrong ip version")
    chunks_v =[rule['value'][idx: idx+2] for idx in range(0,len(rule['value']),2)]
    ports = [int(f"{chunk[1]}{chunk[0]}".replace("0x",""),16) for chunk in chunks_v]
    v = "[{}, ...]".format(', '.join([str(k) for k in ports if k!=0])) if not all(map(lambda x: x==0,ports)) else '*'
    print(f"\t{k} : {v}")

