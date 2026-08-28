<div align="center">
  <img height="125" src="assets/logo.svg"/>
  <h2> TUI for sniffing network traffic using eBPF </h2>
</div>

## 📸 Demo

![](https://github.com/user-attachments/assets/23ab699d-82b3-4b9e-af10-62fbc5d74efd)

## ✨ Features

- Real-time traffic inspection and visualization.
- Comprehensive Traffic Statistics.
- Firewall functionalities.
- Metrics explorer.
- Fuzzy search.

## 🚀 Supported protocols

#### Transport Layer

- [x] TCP
- [x] UDP
- [x] SCTP

#### Network Layer

- [x] IP (v4, v6)
- [x] ICMP (v4, v6)
- [x] IGMP (v1, v2, v3)

#### Link Layer

- [x] ARP

## 💡 Prerequisites

#### A Linux based OS.

Ideally with Linux kernel version 6.10 or higher to ensure all the features to work properly.

> [!NOTE]
> If you're using Debian or Ubuntu, ensure you're on the following minimum versions:
>
> - Debian: Version 13 (Trixie) or newer
> - Ubuntu: Version 24.04 (Noble) or newer

#### Fonts

You might need to install [nerdfonts](https://www.nerdfonts.com/) for the icons to be displayed correctly.

## 🚀 Installation

### 📥 Binary release

You can download the pre-built binaries from the release page [release page](https://github.com/pythops/oryx/releases)

### 🐧Arch Linux

You can install `oryx` from the [extra repository](https://archlinux.org/packages/extra/x86_64/oryx/) with using [pacman](https://wiki.archlinux.org/title/Pacman):

```bash
pacman -S oryx
```

### ⚒️ Build from source

To build `oryx`:

#### 1. Install Rust nightly toolchain

```
rustup toolchain install nightly --component rust-src
```

#### 2. Install [bpf-linker](https://github.com/aya-rs/bpf-linker)

Check [bpf-linker Installation section](https://github.com/aya-rs/bpf-linker?tab=readme-ov-file#installation) .

#### 3. Build

```
cargo xtask build --release
```

This will produce an executable file at `target/release/oryx` that you can copy to a directory in your `$PATH`.

## 🪄 Usage

Run the following command to start `oryx`:

```
sudo oryx
```

> [!NOTE]
> You can start `oryx` with args as well. Check `oryx --help` to see the available options

## 🤝 Contributing

- Strict No LLM.
- Only submit a PR after having a prior issue or discussion.
- Keep PRs small and focused.

## ✍️ Credits

Logo designed by [@ling0x](https://github.com/ling0x)

## ⚖️ License

GPLv3
