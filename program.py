import nmap

# Создаем объект nmap.PortScanner
scanner = nmap.PortScanner()

# Задаем цель для сканирования
target = '127.0.0.1'

# Выполняем сканирование
scanner.scan(target, '1-1024')

# Выводим результаты сканирования
for host in scanner.all_hosts():
    print('Host : %s (%s)' % (host, scanner[host].hostname()))
    print('State : %s' % scanner[host].state())

    for proto in scanner[host].all_protocols():
        print('Protocol : %s' % proto)

        ports = scanner[host][proto].keys()
        for port in ports:
            print('Port : %s\tState : %s' % (port, scanner[host][proto][port]['state']))
