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
    RUST_LOG=info RUST_BACKTRACE=1 cargo xtask run 2> log-file

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

show_maps:
    sudo watch -n3 "python3 maps.py"
