# ESBroadlink

### Introduction
I'm just starting development of python module for communicating with broadlink devices. Old method, used in such application as httpbridge by Ultron, depends on official chineese SDK from broadlink. This SDK support some old devices, such as Broadlink RM, Broadlink RM Pro and some other, but it's not support new devices like Broadlink MP1.

### The main idea
The main idea is very simple: with python scapy I can sniff packets, that official android application sends to the Broadlink device, than I can extract some payload from this packets. There are one little problem: payloads of one code differs from each other by two pair of bytes and broadlink devices doesn't react for one payload, sended more than one time. So, I got two payloads and sends them in rotation, making new UDP packages with scapy support.

### Advantages
* It's completely free and opensource. 
* The code is very compact, simple and readable.
* It's support new devices, at least Broadlink MP1. I can't test with others, because I haven't them.
* It hasn't any exotic dependencies as chineese SDK.
* Obliviously, it's portable. It should be working on MacOS, Linux, Windows.

### Disadvantages
* It needs you to install python and libraries to your android device with official application to scan codes
* It's more complicated to setup than httpbridge, because you should learn broadlink with official application and then scan codes (more operations).
* As I recently learned from 4pda forum, working scheme for sockets SP1, SP2, SP3 is differ, so program shouldn't working with these sockets. Maybe I'll bye one for add functionality.

### Notices
So, at the moment packet scanning rowking with httpbridge 2.2 by altron and e-Control.

### Plans and progress:
1. switching to the official broadlink application ... Done
2. testing with Broadlink MP1 (because I have it) ... Done
3. main functionality ... In progress
4. method for loading pcap dumps
5. method for loading packet capture dumps
6. making api support with bottle framework
7. making setup script to install dependencies
8. making subrepository with saved codes

P.S. Also I'm planning to help anybody, who needs.
