# WiFuzz++

A Wi-Fi fuzzer implemented in C++.
Uses generator coroutines to effortlessly generate fuzzed content.

## Build
Two versions can be build:
 - with GRPC monitor support
 - without

### No GRPC
To build basic version without GRPC monitor support you need to satisfy dependencies:
 - cmake >= 3.17
 - g++ == 10.2.0 (tried newer version on debian produces internal compiler errors)
 - libpcap-dev
 - libspdlog-dev
 - libyaml-cpp-dev
 - libboost-container-dev

For debian:

```shell
apt install g++ cmake libpcap-dev libspdlog-dev libyaml-cpp-dev libboost-container-dev
```

For arch:
```shell
pacman -S cmake gcc make libpcap spdlog yaml-cpp boost --needed
```

#### Build itself
```shell
mkdir build
cd build
cmake ..
make
```

### GRPC

For GRPC monitor support to use with serial port on ESP32 you need additional dependencies.

Additional dependencies:
 - pkgconfig
 - grpc

For arch:

```shell
pacman -S pkgconfig grpc
```

#### Compile protofiles 
To compile protofiles to `.cpp` and `.h` files run in source root directory:
```shell
protoc -I ./proto --cpp_out=build/proto ./proto/monitor.proto
```

#### Build itself
```shell
cd build && make -j
```


## Usage

Produced binary is in `build/src/wifuzz++`

Program takes one argument, which is a config file in `/yaml` format.

### Config file format

Example config can be found in `conf/wifuzz.yaml`.

#### fuzzer_type
Can be one of `"beacon"`, `"prb_resp"`, `"auth"`, `"deauth"`, `"deass"`
```yaml
fuzzer_type: "beacon"
```

#### interface
The wireless interface used for injection.
```yaml
interface: "wlp3s0"
```

#### Random seed
An `unsigned` number to be used for randomized operations. Currently not used.
```yaml
random_seed: 42
```

#### src_mac
An address to be used as fake device in format `"8c:dc:02:12:34:56"`
```yaml
src_mac: "8c:dc:02:12:34:56"
```

#### test_device_mac
An address of the fuzzed device `"3c:71:bf:78:90:12"`
```yaml
test_device_mac: "3c:71:bf:78:90:12"
```

#### controller
The `wait_duration_ms` and `packet_resend_count` affect only frames which are not responses.

```yaml
controller:
    wait_duration_ms: 100
    packet_resend_count: 5
```

#### monitor
Monitor config is different for every type of monitor used.

##### Passive monitor
Passive monitor can be used only with request/response type of frames.
It must be notified by the fuzzer, when frame from the `test_device_mac` is received.

It uses config:
```yaml
monitor:
    type: passive
    timeout_s: 5
```

##### Sniffing monitor
Sniffing monitor performs independent sniffing and resets it's counter when `test_device_mac` is received.

Config:
```yaml
monitor:
    type: snifing
    timeout_s: 50s
    interface: wpl3s0
```

##### GRPC monitor
Must be enabled during compilation.
It runs GRPC server on `server_address` and failures are set, when it is notified from external sources.

Config:
```yaml
monitor:
    type: grpc
    server_address: 0.0.0.0:500051
```


