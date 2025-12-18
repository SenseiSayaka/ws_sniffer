#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <cstring>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iomanip>
#include <zlib.h>

struct WebSocketMessage {
    std::string timestamp;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::vector<uint8_t> payload;
    bool is_masked;
    bool is_compressed;
    uint8_t opcode;
};

class WebSocketSniffer {
private:
    std::vector<WebSocketMessage> captured_messages;
    pcap_t* handle;
    
    // Декомпрессия данных (permessage-deflate)
    bool decompressData(const std::vector<uint8_t>& compressed, std::vector<uint8_t>& decompressed) {
        // WebSocket permessage-deflate требует добавления 0x00 0x00 0xff 0xff в конец
        std::vector<uint8_t> data = compressed;
        data.push_back(0x00);
        data.push_back(0x00);
        data.push_back(0xff);
        data.push_back(0xff);
        
        z_stream stream;
        stream.zalloc = Z_NULL;
        stream.zfree = Z_NULL;
        stream.opaque = Z_NULL;
        stream.avail_in = data.size();
        stream.next_in = const_cast<Bytef*>(data.data());
        
        if (inflateInit2(&stream, -15) != Z_OK) {
            return false;
        }
        
        const size_t CHUNK = 16384;
        decompressed.clear();
        
        do {
            decompressed.resize(decompressed.size() + CHUNK);
            stream.avail_out = CHUNK;
            stream.next_out = decompressed.data() + decompressed.size() - CHUNK;
            
            int ret = inflate(&stream, Z_NO_FLUSH);
            
            if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
                inflateEnd(&stream);
                return false;
            }
            
            if (ret == Z_STREAM_END) {
                decompressed.resize(decompressed.size() - stream.avail_out);
                break;
            }
        } while (stream.avail_out == 0);
        
        inflateEnd(&stream);
        return true;
    }
    
    // Проверка, является ли это WebSocket upgrade
    bool isWebSocketUpgrade(const uint8_t* data, size_t len) {
        std::string str(reinterpret_cast<const char*>(data), std::min(len, size_t(200)));
        return str.find("Upgrade: websocket") != std::string::npos ||
               str.find("Sec-WebSocket") != std::string::npos;
    }
    
    // Парсинг WebSocket фрейма
    bool parseWebSocketFrame(const uint8_t* data, size_t len, WebSocketMessage& msg) {
        if (len < 2) return false;
        
        // Первый байт: FIN, RSV1-3, Opcode
        bool fin = (data[0] & 0x80) != 0;
        msg.is_compressed = (data[0] & 0x40) != 0;  // RSV1 бит указывает на сжатие
        msg.opcode = data[0] & 0x0F;
        
        // Второй байт: MASK, Payload length
        msg.is_masked = (data[1] & 0x80) != 0;
        uint64_t payload_len = data[1] & 0x7F;
        size_t offset = 2;
        
        // Расширенная длина payload
        if (payload_len == 126) {
            if (len < 4) return false;
            payload_len = (static_cast<uint64_t>(data[2]) << 8) | data[3];
            offset = 4;
        } else if (payload_len == 127) {
            if (len < 10) return false;
            payload_len = 0;
            for (int i = 0; i < 8; i++) {
                payload_len = (payload_len << 8) | data[2 + i];
            }
            offset = 10;
        }
        
        // Маска (4 байта, если MASK=1)
        uint8_t mask[4] = {0, 0, 0, 0};
        if (msg.is_masked) {
            if (len < offset + 4) return false;
            memcpy(mask, data + offset, 4);
            offset += 4;
        }
        
        // Проверяем, достаточно ли данных
        if (len < offset + payload_len) {
            // Фрагментированный пакет - пропускаем
            return false;
        }
        
        // Декодирование payload
        std::vector<uint8_t> raw_payload(payload_len);
        for (size_t i = 0; i < payload_len; i++) {
            if (msg.is_masked) {
                raw_payload[i] = data[offset + i] ^ mask[i % 4];
            } else {
                raw_payload[i] = data[offset + i];
            }
        }
        
        // Декомпрессия, если данные сжаты
        if (msg.is_compressed && (msg.opcode == 0x1 || msg.opcode == 0x2)) {
            if (!decompressData(raw_payload, msg.payload)) {
                // Если декомпрессия не удалась, используем сырые данные
                msg.payload = raw_payload;
                msg.is_compressed = false;
            }
        } else {
            msg.payload = raw_payload;
        }
        
        return true;
    }
    
    const char* opcodeToString(uint8_t opcode) {
        switch(opcode) {
            case 0x0: return "Continuation";
            case 0x1: return "Text";
            case 0x2: return "Binary";
            case 0x8: return "Close";
            case 0x9: return "Ping";
            case 0xA: return "Pong";
            default: return "Unknown";
        }
    }
    
    static void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
        WebSocketSniffer* sniffer = reinterpret_cast<WebSocketSniffer*>(user);
        sniffer->processPacket(header, packet);
    }
    
    void printHex(const uint8_t* data, size_t len, size_t max_len = 16) {
        for (size_t i = 0; i < std::min(len, max_len); i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                     << static_cast<int>(data[i]) << " ";
        }
        if (len > max_len) std::cout << "...";
        std::cout << std::dec << std::endl;
    }
    
    void processPacket(const struct pcap_pkthdr* header, const u_char* packet) {
        // Предполагаем Ethernet (14 байт заголовок)
        if (header->caplen < 14) return;
        
        struct ip* ip_header = (struct ip*)(packet + 14);
        
        if (ip_header->ip_p != IPPROTO_TCP) return;
        
        int ip_header_len = ip_header->ip_hl * 4;
        struct tcphdr* tcp_header = (struct tcphdr*)((u_char*)ip_header + ip_header_len);
        int tcp_header_len = tcp_header->th_off * 4;
        
        const u_char* payload = (u_char*)tcp_header + tcp_header_len;
        int payload_len = ntohs(ip_header->ip_len) - ip_header_len - tcp_header_len;
        
        if (payload_len <= 0) return;
        
        // Пропускаем HTTP Upgrade запросы (они не WebSocket фреймы)
        if (isWebSocketUpgrade(payload, payload_len)) {
            return;
        }
        
        // Проверяем, похоже ли это на WebSocket фрейм
        // WebSocket фрейм начинается с байта, где старший бит обычно установлен (FIN=1)
        if (payload_len < 2) return;
        
        // Базовая проверка: первый байт должен иметь валидный opcode
        uint8_t opcode = payload[0] & 0x0F;
        if (opcode > 0x0A && opcode != 0x00) return; // Невалидный opcode
        
        WebSocketMessage msg;
        
        if (parseWebSocketFrame(payload, payload_len, msg)) {
            msg.src_ip = inet_ntoa(ip_header->ip_src);
            msg.dst_ip = inet_ntoa(ip_header->ip_dst);
            msg.src_port = ntohs(tcp_header->th_sport);
            msg.dst_port = ntohs(tcp_header->th_dport);
            
            time_t now = time(nullptr);
            msg.timestamp = ctime(&now);
            msg.timestamp.pop_back(); // Убрать \n
            
            captured_messages.push_back(msg);
            
            std::cout << "   Перехвачено сообщение #" << captured_messages.size() << std::endl;
            std::cout << "   " << msg.src_ip << ":" << msg.src_port 
                     << " -> " << msg.dst_ip << ":" << msg.dst_port << std::endl;
            std::cout << "   Тип: " << opcodeToString(msg.opcode) 
                     << " (0x" << std::hex << (int)msg.opcode << std::dec << ")"
                     << ", Маска: " << (msg.is_masked ? "Да" : "Нет")
                     << ", Сжатие: " << (msg.is_compressed ? "Да" : "Нет")
                     << ", Размер: " << msg.payload.size() << " байт" << std::endl;
            
            // Вывод содержимого
            if (msg.opcode == 0x1 && msg.payload.size() > 0) { // Text frame
                std::string text(msg.payload.begin(), msg.payload.end());
                std::cout << "   📝 Текст: ";
                
                // Проверяем, есть ли управляющие символы (кроме разрешенных)
                // UTF-8 символы (байты > 127) - это нормально!
                bool is_printable = true;
                for (unsigned char c : text) {
                    // Разрешаем: печатные ASCII (>= 32), табы, переводы строк, и все UTF-8 (>= 128)
                    if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
                        is_printable = false;
                        break;
                    }
                }
                
                if (is_printable) {
                    std::cout << text.substr(0, 200);
                    if (text.size() > 200) std::cout << "...";
                } else {
                    std::cout << "[Содержит управляющие символы] ";
                    printHex(msg.payload.data(), msg.payload.size(), 32);
                }
                std::cout << std::endl;
            } else if (msg.opcode == 0x2) { // Binary frame
                std::cout << "     Бинарные данные: ";
                printHex(msg.payload.data(), msg.payload.size(), 32);
            } else if (msg.opcode == 0x8) { // Close frame
                std::cout << "     Закрытие соединения";
                if (msg.payload.size() >= 2) {
                    uint16_t code = (msg.payload[0] << 8) | msg.payload[1];
                    std::cout << ", код: " << code;
                    if (msg.payload.size() > 2) {
                        std::string reason(msg.payload.begin() + 2, msg.payload.end());
                        std::cout << ", причина: " << reason;
                    }
                }
                std::cout << std::endl;
            } else if (msg.opcode == 0x9) {
                std::cout << "      Ping" << std::endl;
            } else if (msg.opcode == 0xA) {
                std::cout << "      Pong" << std::endl;
            }
            
            std::cout << std::endl;
        }
    }
    
public:
    WebSocketSniffer() : handle(nullptr) {}
    
    ~WebSocketSniffer() {
        if (handle) {
            pcap_close(handle);
        }
    }
    
    bool startCapture(const std::string& interface = "", int port = 0) {
        char errbuf[PCAP_ERRBUF_SIZE];
        
        if (interface.empty()) {
            char* dev = pcap_lookupdev(errbuf);
            if (dev == nullptr) {
                std::cerr << "Ошибка поиска устройства: " << errbuf << std::endl;
                return false;
            }
            handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
            std::cout << "Используется интерфейс: " << dev << std::endl;
        } else {
            handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        }
        
        if (handle == nullptr) {
            std::cerr << "Ошибка открытия устройства: " << errbuf << std::endl;
            return false;
        }
        
        struct bpf_program fp;
        std::string filter_exp = "tcp";
        if (port > 0) {
            filter_exp += " port " + std::to_string(port);
        }
        
        if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Ошибка компиляции фильтра" << std::endl;
            return false;
        }
        
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Ошибка установки фильтра" << std::endl;
            return false;
        }
        
        std::cout << "   Начат перехват WebSocket сообщений";
        if (port > 0) std::cout << " на порту " << port;
        std::cout << "..." << std::endl;
        std::cout << "   (Нажмите Ctrl+C для остановки)" << std::endl << std::endl;
        
        pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(this));
        
        // Статистика после остановки
        std::cout << "\n   Захват остановлен" << std::endl;
        std::cout << "   Всего перехвачено сообщений: " << captured_messages.size() << std::endl;
        
        return true;
    }
    
    void stopCapture() {
        if (handle) {
            pcap_breakloop(handle);
        }
    }
    
    void saveMessages(const std::string& filename) {
        if (captured_messages.empty()) {
            std::cout << "    Нет сообщений для сохранения" << std::endl;
            return;
        }
        
        std::ofstream out(filename, std::ios::binary);
        if (!out) {
            std::cerr << "   Ошибка создания файла" << std::endl;
            return;
        }
        
        size_t count = captured_messages.size();
        out.write(reinterpret_cast<const char*>(&count), sizeof(count));
        
        size_t total_size = 0;
        int text_count = 0, binary_count = 0, control_count = 0;
        
        for (const auto& msg : captured_messages) {
            size_t len = msg.timestamp.size();
            out.write(reinterpret_cast<const char*>(&len), sizeof(len));
            out.write(msg.timestamp.c_str(), len);
            
            len = msg.src_ip.size();
            out.write(reinterpret_cast<const char*>(&len), sizeof(len));
            out.write(msg.src_ip.c_str(), len);
            
            len = msg.dst_ip.size();
            out.write(reinterpret_cast<const char*>(&len), sizeof(len));
            out.write(msg.dst_ip.c_str(), len);
            
            out.write(reinterpret_cast<const char*>(&msg.src_port), sizeof(msg.src_port));
            out.write(reinterpret_cast<const char*>(&msg.dst_port), sizeof(msg.dst_port));
            out.write(reinterpret_cast<const char*>(&msg.opcode), sizeof(msg.opcode));
            out.write(reinterpret_cast<const char*>(&msg.is_masked), sizeof(msg.is_masked));
            out.write(reinterpret_cast<const char*>(&msg.is_compressed), sizeof(msg.is_compressed));
            
            len = msg.payload.size();
            out.write(reinterpret_cast<const char*>(&len), sizeof(len));
            out.write(reinterpret_cast<const char*>(msg.payload.data()), len);
            
            total_size += msg.payload.size();
            if (msg.opcode == 0x1) text_count++;
            else if (msg.opcode == 0x2) binary_count++;
            else control_count++;
        }
        
        std::cout << "\n    Сохранение завершено!" << std::endl;
        std::cout << "      Файл: " << filename << std::endl;
        std::cout << "      Всего сообщений: " << count << std::endl;
        std::cout << "      Текстовых: " << text_count << std::endl;
        std::cout << "      Бинарных: " << binary_count << std::endl;
        std::cout << "      Управляющих: " << control_count << std::endl;
        std::cout << "      Общий размер данных: " << total_size << " байт";
        if (total_size > 1024) {
            std::cout << " (" << std::fixed << std::setprecision(2) 
                     << (total_size / 1024.0) << " КБ)";
        }
        std::cout << std::endl << std::endl;
    }
    
    bool loadMessages(const std::string& filename) {
        std::ifstream in(filename, std::ios::binary);
        if (!in) {
            std::cerr << "Ошибка открытия файла" << std::endl;
            return false;
        }
        
        captured_messages.clear();
        size_t count;
        in.read(reinterpret_cast<char*>(&count), sizeof(count));
        
        for (size_t i = 0; i < count; i++) {
            WebSocketMessage msg;
            size_t len;
            
            in.read(reinterpret_cast<char*>(&len), sizeof(len));
            msg.timestamp.resize(len);
            in.read(&msg.timestamp[0], len);
            
            in.read(reinterpret_cast<char*>(&len), sizeof(len));
            msg.src_ip.resize(len);
            in.read(&msg.src_ip[0], len);
            
            in.read(reinterpret_cast<char*>(&len), sizeof(len));
            msg.dst_ip.resize(len);
            in.read(&msg.dst_ip[0], len);
            
            in.read(reinterpret_cast<char*>(&msg.src_port), sizeof(msg.src_port));
            in.read(reinterpret_cast<char*>(&msg.dst_port), sizeof(msg.dst_port));
            in.read(reinterpret_cast<char*>(&msg.opcode), sizeof(msg.opcode));
            in.read(reinterpret_cast<char*>(&msg.is_masked), sizeof(msg.is_masked));
            in.read(reinterpret_cast<char*>(&msg.is_compressed), sizeof(msg.is_compressed));
            
            in.read(reinterpret_cast<char*>(&len), sizeof(len));
            msg.payload.resize(len);
            in.read(reinterpret_cast<char*>(msg.payload.data()), len);
            
            captured_messages.push_back(msg);
        }
        
        std::cout << "  Загружено " << count << " сообщений из " << filename << std::endl;
        return true;
    }
    
    void listMessages() {
        if (captured_messages.empty()) {
            std::cout << "Нет захваченных сообщений" << std::endl;
            return;
        }
        
        std::cout << "\n   Список захваченных сообщений:\n" << std::endl;
        for (size_t i = 0; i < captured_messages.size(); i++) {
            const auto& msg = captured_messages[i];
            std::cout << "[" << i + 1 << "] " << msg.timestamp << std::endl;
            std::cout << "    " << msg.src_ip << ":" << msg.src_port 
                     << " -> " << msg.dst_ip << ":" << msg.dst_port << std::endl;
            std::cout << "    Тип: " << opcodeToString(msg.opcode) 
                     << ", Размер: " << msg.payload.size() << " байт" << std::endl;
            
            if (msg.opcode == 0x1 && msg.payload.size() > 0) {
                std::string text(msg.payload.begin(), msg.payload.end());
                std::cout << "    Превью: " << text.substr(0, 80);
                if (text.size() > 80) std::cout << "...";
                std::cout << std::endl;
            }
            std::cout << std::endl;
        }
    }
    
    bool replayMessage(size_t index, const std::string& target_ip, uint16_t target_port) {
        if (index >= captured_messages.size()) {
            std::cerr << "Неверный индекс сообщения" << std::endl;
            return false;
        }
        
        const auto& msg = captured_messages[index];
        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            std::cerr << "Ошибка создания сокета" << std::endl;
            return false;
        }
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target_port);
        inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);
        
        std::cout << "Повтор сообщения #" << (index + 1) << " на " 
                 << target_ip << ":" << target_port << "..." << std::endl;
        
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "Ошибка подключения" << std::endl;
            close(sock);
            return false;
        }
        
        // Отправка WebSocket Upgrade handshake (упрощенная версия)
        std::string handshake = 
            "GET / HTTP/1.1\r\n"
            "Host: " + target_ip + "\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n";
        
        send(sock, handshake.c_str(), handshake.size(), 0);
        
        char buffer[4096];
        recv(sock, buffer, sizeof(buffer), 0);
        
        // Отправка payload
        send(sock, reinterpret_cast<const char*>(msg.payload.data()), msg.payload.size(), 0);
        
        std::cout << " Сообщение отправлено!" << std::endl;
        
        close(sock);
        return true;
    }
};

int main(int argc, char* argv[]) {
    std::cout << "╔══════════════════════════════════════════╗" << std::endl;
    std::cout << "║  WebSocket Sniffer & Replay Tool v2      ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
    
    WebSocketSniffer sniffer;
    
    std::cout << "Режимы работы:" << std::endl;
    std::cout << "1. Захват сообщений (требуются права root/admin)" << std::endl;
    std::cout << "2. Просмотр сохраненных сообщений" << std::endl;
    std::cout << "3. Повтор сообщения" << std::endl;
    std::cout << "\nВыберите режим (1-3): ";
    
    int mode;
    std::cin >> mode;
    
    if (mode == 1) {
        std::string interface;
        int port = 0;
        
        std::cout << "Интерфейс (пусто для автоопределения, 'lo' для localhost): ";
        std::cin.ignore();
        std::getline(std::cin, interface);
        
        std::cout << "Фильтр по порту (0 для всех портов): ";
        std::cin >> port;
        
        sniffer.startCapture(interface, port);
        
        std::cout << "\nСохранить захваченные сообщения? (y/n): ";
        char save;
        std::cin >> save;
        if (save == 'y' || save == 'Y') {
            sniffer.saveMessages("captured_messages.dat");
        }
    } 
    else if (mode == 2) {
        if (sniffer.loadMessages("captured_messages.dat")) {
            sniffer.listMessages();
        }
    }
    else if (mode == 3) {
        if (sniffer.loadMessages("captured_messages.dat")) {
            sniffer.listMessages();
            
            std::cout << "Номер сообщения для повтора: ";
            size_t idx;
            std::cin >> idx;
            
            std::string ip;
            uint16_t port;
            std::cout << "IP адрес назначения: ";
            std::cin >> ip;
            std::cout << "Порт назначения: ";
            std::cin >> port;
            
            sniffer.replayMessage(idx - 1, ip, port);
        }
    }
    
    return 0;
}
