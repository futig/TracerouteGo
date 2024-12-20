# traceroute-go
Утилита, написанная на golang, предназначенная для определения маршрутов следования данных в сетях TCP/IP.

Чтобы запустить, нужно сделать следующее:

1. В файле config.ini изменить конфигруацию, на используемую хостом
2. запустить main.go от имени администратора с нужными параметрами traceroute

Утилита запускается следующим образом:
```
traceroute [OPTIONS] IP_ADDRESS {tcp|udp|icmp}
```

Примечание: на windows не работает
