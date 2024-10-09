set export

# List available targets
default:
    just --list

# Remove all the TC for a specific interface
clean interface:
    sudo tc filter del dev $interface egress
    sudo tc filter del dev $interface ingress

# Show TC for a specific interface
show interface:
    sudo tc filter show dev $interface ingress
    sudo tc filter show dev $interface egress

# Run oryx debug
run-debug:
    echo "" > log-file
    RUST_LOG=info cargo xtask run 2> log-file

run:
    cargo xtask run

# Run oryx debug
release:
    cargo xtask run --release

# Build oryx
build:
    cargo xtask build

# Profile
profile:
    CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph  --root --bin oryx

show_active_maps:
    @for MAPTYPE in BLOCKLIST_IPV4 BLOCKLIST_IPV6;do \
        map_ids=$(sudo bpftool map show | grep "$MAPTYPE" | cut -f1 -d":" ); \
        for map_id in $map_ids;do \
            echo "$MAPTYPE($map_id)";\
            sudo bpftool map dump id $map_id -j  | python3 showmaps.py 2>/dev/null || echo "\tempty";\
        done ;\
    done
