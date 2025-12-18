Быстрый тест полного цикла
1. Скомпилируйте снифер:
g++ -o ws_sniffer ws_sniffer.cpp -lpcap -lz -std=c++11

2. Запустите в 3 терминалах:
Терминал 1 - Сервер:
python3 ws_test_server.py

Терминал 2 - Снифер:
sudo ./ws_sniffer
Выберите: 1
Интерфейс: lo
Порт: 8765

Терминал 3 - Клиент:
python3 ws_test_client.py
Выберите: 1 (автоматический режим)
