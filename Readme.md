<div align="center">
  <h2> TUI for sniffing network traffic using eBPF </h2>
</div>

## 📸 Demo

![](https://github.com/user-attachments/assets/f6960d39-1d03-42d5-9601-a41619998f2a)

## ✨ Features

- Real-time traffic inspection and visualization.
- Comprehensive Traffic Statistics.
- Fuzzy search.

## 💡 Prerequisites

A Linux based OS.

> [!NOTE]
> You might need to install [nerdfonts](https://www.nerdfonts.com/) for the icons to be displayed correctly.

## 🚀 Installation

### 📥 Binary release

You can download the pre-built binaries from the release page [release page](https://github.com/pythops/oryx/releases)

### ⚒️ Build from source

To build `oryx`:

#### 1. Install Rust nightly toolchain

```
rustup toolchain install nightly --component rust-src
```

#### 2. Install [bpf-linker](https://github.com/aya-rs/bpf-linker)

##### For `x86_64`

Simply run the following command:

```
cargo install bpf-linker
```

##### For `arm64`

For Debian based distributions, make sure you have the following dependencies installed:

- `llvm-19`
- `llvm-19-dev`
- `libpolly-19-dev`

then run the following command:

```
cargo install bpf-linker --no-default-features
```

> Check [bpf-linker Installation section](https://github.com/aya-rs/bpf-linker?tab=readme-ov-file#installation) for more infos.

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

## ⌨️ Key Bindings

`?`: Show help.

`Tab` or `Shift + Tab`: Switch between different sections.

`j` or `Down` : Scroll down.

`k` or `Up`: Scroll up.

`esc`: Dismiss the different pop-ups and modes.

`q` or `ctrl + c`: Quit the app.

`Space`: Select/Deselect interface or filter.

`f`: Update the applied filters.

`i`: Show more infos about the selected packet.

`ctrl + r`: Reset the app.

`ctrl + s`: Export the capture to `~/oryx/capture` file.

`/`: Start fuzzy search.

## ⚖️ License

GPLv3
