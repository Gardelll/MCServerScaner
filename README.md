# MCServerScaner
Scan all the mc server in the IPv4 scope.

This program will traverse all public addresses in the IPv4 scope and try to connect to port 25565.
It can print the IP address, Minecraft version and the MOTD of the server.

## Compile
### Windows
Use Visual Studio
```
msbuild
```
### Linux
Use gcc
```
g++ -std=c++11 -pthread -o McScan McScan.cpp jsoncpp.cpp -Iinclude
```
