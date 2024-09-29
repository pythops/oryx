# Components Description

## phases
- Startup
- Sniffing


## popups
- help
- update_filters
- packet_info
- firewall rule editing

## section
- packets
- stats
- alert
- firewall

## notification
---
# Rendering
## startup (phase)
- help (popup)
- Interface
- TransportFilter
- NetworkFilter
- LinkFilter
- TrafficDirection
- Start


## sniffing (phase)
- help (popup)
- update_filters (popup)
- sections

### packet (section)
- fuzzy
- packet_info (popup)

### stats (section)
- None

### alert (section)
- dynamic header

### firewall (section)
- editing (popup)

---

struct Phase:
- handle_keys_events
- render
- popups: 

struct section:
- handle_keys_events
- render
- popups


