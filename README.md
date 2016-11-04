# ESBroadlink

### Introduction
I'm just starting development of python module for communicating with broadlink devices. Old method, used in such application as httpbridge by Ultron, depends on official chineese SDK from broadlink. This SDK support some old devices, such as Broadlink RM, Broadlink RM Pro and some other, but it's not support new devices like Broadlink MP1.

### The main idea
The main idea is very simple: with python scapy I can sniff packets, that official android application sends to the Broadlink device, than I can extract some payload from this packets. There are one little problem: payloads of one code differs from each other by two pair of bytes and broadlink devices doesn't react for one payload, sended more than one time. So, I got two payloads and sends them in rotation, making new UDP packages with scapy support.

### Advantages
* It's completely free and opensource. 
* The code is very compact, simple and readable.
* I hope, it will support new devices, that can't be used with old sdk.
* It hasn't any exotic dependencies as chineese SDK.
* Obliviously, it's portable. It should be working on MacOS, Linux, Windows.

### Disadvantages
* It needs you to install python and libraries to your android device with official application to scan codes
* It's more complicated to setup than httpbridge, because you should learn broadlink with official application and then scan codes (more operations).

### Notices
So, at the moment I'm using httpbridge 2.2 by altron as a packets source. 

### Plans:
1. switching to the official broadlink application
2. testing with Broadlink MP1 (because I have it)
3. method for loading pcap dumps
4. method for loading packet capture dumps
5. making api support with bottle framework
6. making compatible with python3
7. making setup script to install dependencies
8. making subrepository with saved codes

P.S. Also I'm planning to help anybody, who needs.
