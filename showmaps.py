import sys,json;
rules=json.loads(sys.stdin.read())
for rule in rules:
    k = '.'.join([str(int(x,16)) for x in rule['key']])
    chunks =[rule['value'][idx: idx+2] for idx in range(0,len(rule['value']),2)]
    ports = [int(f"{chunk[1]}{chunk[0]}".replace("0x",""),16) for chunk in chunks]
    v = "[{}, ...]".format(', '.join([str(k) for k in ports if k!=0])) if not all(map(lambda x: x==0,ports)) else '*'
    print(f"\t{k} : {v}")

