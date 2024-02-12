#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h> // Для доступа к TCP-заголовку

#define PORT 12345 

// Максимальное количество заблокированных IP-адресов
#define MAX_BLOCKED_IPS 100

// Структура для хранения заблокированных IP-адресов
struct BlockedIPs {
    char ip_address[INET_ADDRSTRLEN];
    int count;
};

struct BlockedIPs blocked_ips[MAX_BLOCKED_IPS];
int num_blocked_ips = 0;

// Функция для блокировки IP-адреса
void block_ip(const char *ip_address) {
    // Проверяем, не заблокирован ли уже этот IP-адрес
    for (int i = 0; i < num_blocked_ips; i++) {
        if (strcmp(blocked_ips[i].ip_address, ip_address) == 0) {
            return;
        }
    }

    char command[100];
    snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP", ip_address);
    system(command);

    // Добавляем заблокированный IP в список
    if (num_blocked_ips < MAX_BLOCKED_IPS) {
        strcpy(blocked_ips[num_blocked_ips].ip_address, ip_address);
        blocked_ips[num_blocked_ips].count = 1;
        num_blocked_ips++;
    }


    // Добавляем заблокированный IP в файл
    FILE *blocked_file = fopen("blocked_ips.txt", "a");
    if (blocked_file == NULL) {
        perror("fopen");
        return;
    }
    fprintf(blocked_file, "%s\n", ip_address);
    fclose(blocked_file);
}

// Функция для логирования инцидента
void log_incident(const char *ip_address) {
    FILE *logfile = fopen("scan_log.txt", "a"); 
    if (logfile == NULL) {
        perror("fopen");
        return;
    }
    fprintf(logfile, "Scan attempt from: %s\n", ip_address); // Запись в файл информации об инциденте
    fclose(logfile); 
}

// Функция для отправки уведомления в Telegram (в будущем)
//void send_telegram_notification(const char *ip_address) {}

int main() {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    // Создание TCP сокета
    if ((server_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Задание параметров сокета
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Привязка сокета к заданному порту
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Принятие входящих соединений и анализ пакетов
    while(1) {
        struct sockaddr_in client_address;
        socklen_t client_addrlen = sizeof(client_address);
        char packet[8192];
        
        ssize_t packet_size = recvfrom(server_fd, packet, sizeof(packet), 0, (struct sockaddr *)&client_address, &client_addrlen);
        if (packet_size < 0) {
            perror("recvfrom");
            continue;
        }

        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 20); // Смещение 20 байт для IP заголовка

        // Проверяем флаги TCP, если установлен флаг SYN и сброшены флаги ACK и RST, это может быть скрытое сканирование
        if (tcp_header->syn && !tcp_header->ack && !tcp_header->rst) {
            // Получение IP-адреса клиента
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(client_address.sin_addr), client_ip, INET_ADDRSTRLEN);
            printf("Connection from %s:%d\n", client_ip, ntohs(client_address.sin_port));

            // Действия при обнаружении попытки сканирования
            log_incident(client_ip); // Логирование инцидента
            //send_telegram_notification(client_ip); // Отправка уведомления в Telegram
            block_ip(client_ip); // Блокировка IP-адреса
        }
    }

    return 0;
}
