# Windows Filtering Platform

Копия MIT-пакета tunnel/firewall из golang.zx2c4.com/wireguard/windows v1.0.1.
Исходный код: https://git.zx2c4.com/wireguard-windows/tree/tunnel/firewall?h=v1.0.1
Сохранены авторские заголовки, лицензия и ABI-тесты.

Изменение OpenFlux: если у процесса нет service SID (S-1-5-80-...),
getCurrentProcessSecurityDescriptor использует SID пользователя процесса.
Правило по-прежнему требует одновременно путь EXE и SID: остальные программы
пользователя не получают обход туннеля. Это позволяет запускать ядро через
UAC, без регистрации службы Windows. Динамические фильтры и блокировка
IPv4/IPv6 остаются включены; ошибка установки останавливает подключение.
