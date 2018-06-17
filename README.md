# EasyScanner

A simple and convenience network scanner, included host discovery and ports scanning.

## Feature

- 支持目标网段与目标端口范围的控制
- 支持使用多种预设扫描策略进行扫描
	- 主机发现
		- 构造异常 IP Package 扫描
		- 基于 ICMP 扫描
		- 基于 ARP 扫描
	- 端口扫描
		- TCP SYN 扫描
		- TCP CONNECTION 扫描
		- TCP ACK 扫描
		- UDP 扫描
- 支持多线程扫描
- 支持使用隐匿性策略进行扫描
  - 采用随机扫描顺序
  - 构造数据包时采用随机化赋值

## Usage

- 主机发现
	```
	-d <icmp/arp/ip> -t <target>
	```
	eg: `main.py -d arp -t 192.168.1.0/24`

- 端口扫描
	```
	-s <S/A/C/U> -t <target>/<target:port>/<target:lport-hport>
	```
	eg: `main.py -s S -t 192.168.1.1:1-1024`

- 自动获取指定网络信息，即先扫描存活主机，再对存活主机进行端口扫描
	```
	-a -t <targe>
	```
	eg: `main.py -a -t 192.168.1.0/24`

## License

The EasyScanner is under the MIT License.