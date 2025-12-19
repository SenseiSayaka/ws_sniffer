# WebSocket Sniffer

Инструмент для захвата и анализа WebSocket трафика. Позволяет
перехватывать и декодировать WebSocket сообщения для отладки и
мониторинга сетевого взаимодействия.

## Описание

**ws_sniffer** --- это мощный анализатор WebSocket трафика, написанный
на C++ с использованием libpcap. Проект включает тестовый сервер и
клиент на Python для демонстрации и тестирования функциональности.

## Технологический стек

-   **Язык**: Python (99.4%), C++
-   **WebSocket библиотека**: websockets
-   **Захват трафика**: libpcap
-   **Сжатие**: zlib

## Зависимости

``` bash
sudo apt-get install zlib1g-dev libpcap-dev
pip install websockets
```

## Быстрый старт

### 1. Компиляция снифера

``` bash
g++ -o ws_sniffer ws_sniffer.cpp -lpcap -lz -std=c++11
```

### 2. Запуск тестового сценария (в 3 терминалах)

**Терминал 1 --- WebSocket сервер:**

``` bash
python3 test_server.py
```

**Терминал 2 --- Сниффер:**

``` bash
sudo ./ws_sniffer
```

Выберите интерфейс (например, `lo` или `eth0`) и порт (`8765`).

**Терминал 3 --- WebSocket клиент:**

``` bash
python3 test_client.py
```

Выберите режим: автоматический (1) или ручной (2).

## Структура проекта

    ws_sniffer/
    ├── ws_sniffer.cpp
    ├── ws_sniffer
    ├── test_server.py
    ├── test_client.py
    ├── captured_messages.dat
    └── README.md

## Компоненты

### test_server.py

-   Асинхронный WebSocket сервер на основе библиотеки `websockets`
-   Эхо-ответы и broadcasting
-   Логирование подключений и сообщений

### test_client.py

-   Два режима работы (авто/ручной)
-   Поддержка UTF-8, JSON, эмодзи
-   Интерфейс для ручного ввода сообщений

### ws_sniffer (C++)

-   Захват WebSocket трафика на уровне пакетов
-   Декодирование WebSocket фреймов
-   Распаковка сжатых сообщений (zlib)
-   Сохранение данных в файл


