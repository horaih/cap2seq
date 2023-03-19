# cap2seq
cap2sec is used to generate a sequence diagram for 5G system. The project is aimed to investigate how the 5GC works well.

## Getting Started
### Prerequisites

* Rust environment on a Linux server to run cap2seq.
  - The project is tested on Debian GNU/Linux 11 (bullseye) on Raspberry Pi.

* preparing a capture file.
  - The project is tested by using https://github.com/telekom/5g-trace-visualizer/blob/master/doc/free5gc.pcap

### Installing and some examples.
* Download cap2seq and show its usage.

  ```
  $ git clone https://github.com/horaih/cap2seq.git
  $ cd cap2seq
  $ cargo run -- --help
   Compiling cap2seq v0.1.0 (/home/horai/repos/cap2seq)
    Finished dev [unoptimized + debuginfo] target(s) in 6.12s
     Running `target/debug/cap2seq --help`
  Usage: cap2seq [OPTIONS] --pcapfile <PCAPFILE>

  Options:
    -f, --pcapfile <PCAPFILE>          
    -p, --http2ports <PORT NUMBER(s)>  
    -i, --imsi <IMSI>                  
    -h, --help                         Print help
  ```

* show IMSI list used in the pcap file.
  ```
  $ cargo run -- --pcapfile $somewhere/free5gc.pcap -http2ports 29502,29503,29504,29507,29509,29518
  following imsi(s) found.
  2089300007487
  ```
  
* generate sequence diagram for the specified IMSI.
  ```
  $ cargo run -- --pcapfile $somewhere/free5gc.pcap -http2ports 29502,29503,29504,29507,29509,29518 --imsi 2089300007487
  (To be implemented)
  ```
