import json
import subprocess
import yaml
from functools import partial

def hex2int(hex):
    return int(hex.replace("0x", ""), 16)


def parse_ipv4(rule):
    k = ".".join(reversed([str(hex2int(k)) for k in rule["key"]]))
    chunks_v = [rule["value"][idx : idx + 2] for idx in range(0, len(rule["value"]), 2)]
    ports = [hex2int(f"{chunk[1]}{chunk[0]}") for chunk in chunks_v]
    v = (
        "[{}, ...]".format(", ".join([str(k) for k in ports if k != 0]))
        if not all(map(lambda x: x == 0, ports))
        else "*"
    )
    return {k: v}

def parse_ipv6(rule):
    chunks_k = [rule["key"][idx : idx + 2] for idx in range(0, len(rule["key"]), 2)]
    k = ":".join(
        reversed([str(hex2int(f"{chunk[1]}{chunk[0]}")) for chunk in chunks_k])
    )
    chunks_v = [rule["value"][idx : idx + 2] for idx in range(0, len(rule["value"]), 2)]
    ports = [hex2int(f"{chunk[1]}{chunk[0]}") for chunk in chunks_v]
    v = (
        "[{}, ...]".format(", ".join([str(k) for k in ports if k != 0]))
        if not all(map(lambda x: x == 0, ports))
        else "*"
    )
    return {k: v}




filter_idx_map = dict(
    transport={0: "tcp", 1: "udp"},
    network={0: "ipv4", 1: "ipv6", 2: "icmp"},
    link={0: "arp"},
)


def parse_filter(rule, filter_type):
    idx = hex2int(rule["key"][0])
    flag = hex2int(rule["value"][0])
    idx_map = filter_idx_map[filter_type]
    if idx in idx_map:
        filter_name = idx_map[idx]
        return {filter_name: "❌" if flag else "✔️"}


def parse_traffic_filter(rule):
    flag = hex2int(rule["value"][0])
    return {"status": "❌" if flag else "✔️"}



def parse_ingress_egress(rule):
    return {"type":"ingress" if rule["value"][0] == "0xff" else "egress"}


def fmt_maps(ebpfs,maps):
    ingress_maps = []
    egress_maps = []
    ingress_egress = {k: v for k,v in maps.items() if v["name"]==".rodata"}
 
    for idx,in_eg_map in ingress_egress.items():
        map_type = in_eg_map["elements"][0]["type"]
      
        out_map = ingress_maps if map_type =="ingress" else egress_maps
        for map_group in ebpfs:

            if idx in map_group:
                for map_idx in map_group:
                    if map_idx in maps:
                        out_map.append(maps[map_idx])
       
    outputs = {}
    for fmted_map in (ingress_maps,egress_maps):
        res = {m["name"]: {k:v  for el in m["elements"]  for k,v in el.items() } for m in fmted_map}    
        filters = {"direction":res["TRAFFIC_DIRECTI"],"link":res["LINK_FILTERS"],"transport":res["TRANSPORT_FILTE"],"network":res["NETWORK_FILTERS"]}
        firewall = {"ipv4":res["BLOCKLIST_IPV4"],"ipv6":res["BLOCKLIST_IPV6"]}
        outputs[res[".rodata"]["type"]]=dict(filters=filters,firewall=firewall)
    return outputs







to_display_maps = {
     ".rodata": parse_ingress_egress,
    "BLOCKLIST_IPV4": parse_ipv4,
    "BLOCKLIST_IPV6": parse_ipv6,
    "LINK_FILTERS": partial(parse_filter, filter_type="link"),
    "TRANSPORT_FILTE": partial(parse_filter, filter_type="transport"),
    "NETWORK_FILTERS": partial(parse_filter, filter_type="network"),
    "TRAFFIC_DIRECTI": parse_traffic_filter,
   
}


map_info_cmd = lambda _id: ["bpftool", "--json", "map", "dump", "name", str(_id)]
prog_map_cmd = lambda _id: ["bpftool", "--json", "prog", "show", "name", str(_id)]


try:
    ebpfs = []
    ebpfs = json.loads(subprocess.check_output(prog_map_cmd("oryx")).decode())
    ebpfs=[prog["map_ids"] for prog in ebpfs]
  
    
    maps = {}
    for map_name, func in to_display_maps.items():
        active_maps = json.loads(
            subprocess.check_output(map_info_cmd(map_name)).decode()
        )

        for active_map in active_maps:
            elements = active_map.get("elements", [])
            _id = active_map.get("id")
            maps[_id] = dict(name=map_name,elements=[])
            for el in elements:
                if x := func(el):
                    maps[_id]["elements"].append(x)
    out = fmt_maps(ebpfs,maps)
    print(yaml.dump(out,indent=2,allow_unicode=True))
        
    
except:
    print("")
