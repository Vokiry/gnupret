<div align="center">

# 🐧 gnupret (Linux) 🎧📺

### Комфортный Linux-адаптер для [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube)

Основан на движке **`nfqws`** из оригинального [bol-van/zapret](https://github.com/bol-van/zapret) и стратегиях [Flowseal](https://github.com/Flowseal/zapret-discord-youtube).

[![Linux](https://img.shields.io/badge/OS-Linux-FCC624?style=flat&logo=linux&logoColor=black)](#)
[![Python 3](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)](#)
[![nftables](https://img.shields.io/badge/Firewall-nftables%20%2F%20iptables-red?style=flat)](#)
[![systemd](https://img.shields.io/badge/Init-systemd-blue?style=flat)](#)

</div>

---

## ⚡ Особенности `gnupret`

- **Полная совместимость со стратегиями Flowseal:** Все 22 стратегии (`general`, `ALT1`–`ALT13`, `FAKE TLS AUTO`, `SIMPLE FAKE`, `EXP`) работают нативно через `nfqws` с теми же фейковыми пакетами (`quic_initial_*.bin`, `ACTIVE_DISCORD_UDP.bin`, `tls_clienthello_*.bin`).
- **Удобное интерактивное меню (TUI):** Полный аналог привычного `service.bat` для терминала Linux.
- **Чистый сетевой фильтр:**
  - Используется изолированная таблица **`nftables`** (`table inet gnupret`).
  - При выходе или остановке службы таблица удаляется целиком — **никаких повисших правил**, конфликтов с Docker, VPN или UFW.
  - Флаг `bypass` на очередях NFQUEUE гарантирует, что интернет не зависнет при перезапуске процесса.
- **Автономный бинарник `nfqws`:** В комплекте статически скомпилированный бинарник от bol-van без внешних библиотечных зависимостей (работает на Arch, Ubuntu, Debian, Fedora и др.).
- **Интеграция с systemd:** Установка, включение в автозагрузку и управление службой в одну команду или прямо из меню.
- **Встроенный бенчмарк стратегий:** Проверка доступности YouTube и Discord по всем стратегиям сразу, чтобы быстро найти рабочую под вашего провайдера.
- **Обновление hosts:** Починка голосовых каналов Discord и Telegram Web обновлением `/etc/hosts` с безопасной разметкой секций.

---

## 🚀 Быстрый старт

### 1. Требования

- Python 3.8+
- `nftables` (рекомендуется) или `iptables`
- Права суперпользователя (`sudo`)

### 2. Запуск интерактивного меню

```bash
sudo ./gnupret
```

Откроется меню, аналогичное Windows-версии `service.bat`:

```text
============================================================
             GNUPRET SERVICE MANAGER (Linux)
   Strategy:    ALT2 (alt2.conf)
   Process:     RUNNING (PID: 1234)
   Systemd:     Active & Enabled
   Game Filter: DISABLED [TCP/UDP 1024-65535]
   IPSet Mode:  LOADED (lists/ipset-all.txt)
   Interface:   auto (enp8s0)
============================================================

  :: CONTROLS
     1. Run in Console (Foreground test mode with live logs)
     2. Stop Background Process
     3. Select Strategy

  :: SERVICE (systemd)
     4. Reinstall / Enable Service
     5. Remove / Disable Service
     6. Restart Service

  :: SETTINGS
     7. Game Filter Toggle   [DISABLED]
     8. IPSet Filter Toggle  [LOADED]

  :: TOOLS & UPDATES
     9. Run Target Tests (YouTube, Discord, etc.)
     10. Auto-Benchmark All Strategies (Find best)
     11. Update /etc/hosts (Discord Voice & Telegram)
     12. Update IPSet & Hostlists from GitHub
     13. Run Diagnostics

  ----------------------------------------------------------
     0. Exit
```

---

## 💻 Использование через консоль (CLI)

`gnupret` поддерживает как интерактивный режим, так и прямые команды терминала:

### Управление процессом
```bash
# Тестовый запуск стратегии в консоли с логами (Ctrl+C для выхода)
sudo ./gnupret run alt2

# Фоновый запуск выбранной или указанной стратегии
sudo ./gnupret start alt2

# Остановка фонового процесса и очистка правил файрвола
sudo ./gnupret stop

# Текущий статус (процесс, таблица nftables, конфликты)
sudo ./gnupret status
```

### Выбор и просмотр стратегий
```bash
# Список всех доступных стратегий
./gnupret list

# Выбор стратегии по умолчанию
./gnupret select alt2
```

### Системная служба (systemd)
```bash
# Установить и запустить службу в автозагрузку
sudo ./gnupret service install

# Статус службы
sudo ./gnupret service status

# Перезапуск службы
sudo ./gnupret service restart

# Удалить службу из автозагрузки
sudo ./gnupret service remove
```

### Проверка работоспособности и бенчмарк
```bash
# Проверить доступность целей (YouTube, Discord, Google, Cloudflare)
./gnupret test

# Авто-бенчмарк: перебирает все стратегии и тестирует их
sudo ./gnupret test-all
```

### Настройки и списки
```bash
# Режим Game Filter: disabled, all, tcp, udp
sudo ./gnupret game-filter all

# Режим IPSet фильтра: loaded, none, any
sudo ./gnupret ipset loaded

# Обновить /etc/hosts для Discord Voice и Telegram
sudo ./gnupret hosts update

# Очистить /etc/hosts от записей gnupret
sudo ./gnupret hosts remove
```

---

## 📁 Структура проекта

```text
gnupret/
├── gnupret                 # Исполняемый файл запуска
├── src/                    # Модули Python
│   ├── config.py           # Конфигурация и пути
│   ├── strategy.py         # Парсер и реестр стратегий
│   ├── firewall.py         # Менеджер nftables и iptables
│   ├── runner.py           # Запуск и мониторинг nfqws
│   ├── systemd.py          # Интеграция со службой systemd
│   ├── hosts.py            # Обновление /etc/hosts
│   ├── tester.py           # Тестирование и бенчмарк
│   ├── tui.py              # Интерактивное терминальное меню
│   └── cli.py              # CLI диспетчер команд
├── bin/                    # Бинарник nfqws и фейковые пакеты (.bin)
├── lists/                  # Списки хостов и IP (YouTube, Google, Discord)
├── strategies/             # Нативные конфигурации стратегий (.conf)
└── utils/
    └── targets.txt         # Целевые адреса для проверки доступности
```

---

## 🤝 Благодарности

- [bol-van](https://github.com/bol-van/zapret) — автор оригинального zapret и утилиты `nfqws`.
- [Flowseal](https://github.com/Flowseal/zapret-discord-youtube) — подбор и сопровождение актуальных стратегий для Discord и YouTube.
