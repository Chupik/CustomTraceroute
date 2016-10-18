//
//  main.c
//  CustomTraceroute
//
//  Created by Alexandr on 16.05.15.
//  Copyright (c) 2015 Alexandr. All rights reserved.
//

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>

#define PROCEDURE

//ДЕКЛАРАЦИИ
//заголовок IP-датаграммы
struct IPHEADER
{
    unsigned char version;          //1     1   версия ip-протокола
    unsigned char typeOfService;    //1     2   TOS
    unsigned short length;          //2     4   длина датаграммы
    unsigned short id;              //2     6   идентификатор
    unsigned short flags;           //2     8   флаги
    unsigned char timeToLeave;      //1     9   время ожидания
    unsigned char protocol;         //1     10  тип протокола
    unsigned short checksum;        //2     12  чексумма
    unsigned int sourceIP;          //4     16  ip отправителя
    unsigned int destIP;            //4     20  ip назначения
};

//заголовок ICMP-датаграммы
struct ICMPHEADER
{
    unsigned char type;         //тип                       1   21
    unsigned char code;         //код                       2   22
    unsigned short checksum;    //чексумма по RFC 1071      4   24
    unsigned short id;          //идентификатор процесса    6   26
    unsigned short seqNumber;   //номер пакета порядковый   8   28
} __attribute__((packed));

//структура сообщения ICMP
struct ICMPREQUEST
{
    struct ICMPHEADER header;
    struct timeval time;                                      //      4  32
} __attribute__((packed));

//структура для исходящего сообщения
struct ICMPPACKET
{
    struct ICMPREQUEST icmpRequest;
};

//структура для входящего сообщения (приделан IP-заголовок)
struct ICMPINPACKET
{
    struct IPHEADER ipHeader;
    struct ICMPREQUEST icmpRequest;
};


//процедура вычисления чексумм по RFC 1071
PROCEDURE long getChecksum(unsigned char *addr, int count)
{
    /* Расчет контрольной суммы Internet для count байтов,
     * начиная с addr.
     */
    //декларации
    unsigned int sum = 0;                   //переменная для хранения чексуммы
    
    printf(" *Процедура getChecksum\n");
    
    while( count > 1 )  {
        /*  складываем по два байта */
        sum += (*addr << 8) + *(addr + 1);
        addr += 2;
        count -= 2;
    }
    
    /*  сколько раз был перенос, столько и прибавляем */
    sum += (sum >> 16);
    
    sum = ~sum & 0xffff;
    
    sum = sum << 8;
    sum += sum >> 16;
    
    return sum & 0xffff;
}

//процедура завершения работы
PROCEDURE void myfinish()
{
    printf(" *Программа завершила свою работу, system time: %li\n", time(0));
    _exit(0);
}


//процедура обработки и вывода ошибки
PROCEDURE void serveError()
{
    printf(" *Процедура serveError\n");
    printf(" ERROR: %s\n", strerror(errno));
    myfinish();
}

//процедура проверки исходных данных
PROCEDURE int mystart(struct sockaddr_in *destAddr, int argc, const char * argv[], int *rawSocket)
{
    //декларации
    struct timeval timeOut;     //структура для хранения времени
    const char *addrName;             //строка для адреса
    
    printf(" *Процедура mystart\n");
    
    printf("Программа Traceroute для Linux. Версия 0.1 alpha. Автор: Кочупалов Александр.\n");
    
    *rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);                        //получаем дескриптор сокета и создаем его
    
    if (*rawSocket == -1)
        serveError();
    
    timeOut.tv_sec = 3;                                                         //устанавливаем таймаут ожидания блокирующего сокета
    timeOut.tv_usec = 0;
    setsockopt(*rawSocket, SOL_SOCKET, SO_SNDTIMEO, &timeOut, sizeof(timeOut));  //устанавливаем таймаут
    setsockopt(*rawSocket, SOL_SOCKET, SO_RCVTIMEO, &timeOut, sizeof(timeOut));  //3 секунды
    
    destAddr->sin_family = AF_INET;                                             //тип адреса - глобальный
    destAddr->sin_port = 34454;                                                     //порт - не имеет значения
    
    
    switch (argc)
    {
            //если ввели только адрес узла
        case 2:
            //сырой сокет, прийдется запускать под рутом
            addrName = argv[1];
            printf(" *Введен адрес %s, вывод в консоль\n", argv[1]);
            destAddr->sin_addr.s_addr = inet_addr(addrName);
            return 1;
            break;
            //если ничего не ввели
        case 1:
            //сырой сокет, прийдется запускать под рутом
            addrName = "127.0.0.1";
            printf(" *Не введен адрес, localhost по умолчанию, вывод в консоль\n");
            destAddr->sin_addr.s_addr = inet_addr(addrName);
            return 2;
            break;
        default:
            return 0;
            break;
    }
}

//процедура формирования заголовка ICMP
PROCEDURE void setupOutPacket(struct ICMPPACKET *packet, unsigned short seqNumber)
{
    //декларации
    struct timeval requestTime;                                //структура для хранения времени запроса
    
    printf(" *Процедура setOutPacket\n");
    
    gettimeofday(&requestTime, DST_NONE);               //получаем текущее время
    
    packet->icmpRequest.header.checksum = 0;            //перед вычислением чексуммы, она должны быть установлена в ноль
    packet->icmpRequest.header.code = 0;                //код 0 - для эхо-запроса не нужен код
    packet->icmpRequest.header.id = getpid();           //в качестве идентификатора рекомендуется указывать ID процесса
    packet->icmpRequest.header.type = 8;                //тип 8 - эхо запрос
    
    packet->icmpRequest.header.seqNumber = seqNumber;   //номер в последовательности по порядку
    packet->icmpRequest.header.checksum = 0;
    packet->icmpRequest.time = requestTime;             //устанавливаем timestamp
    packet->icmpRequest.header.checksum = getChecksum((unsigned char *)&packet->icmpRequest, sizeof(packet->icmpRequest));
    //вычисляем чексумму
}


//процедура хопа
PROCEDURE int oneTrace(int rawSocket, struct sockaddr_in *destAddr, unsigned int ttl)
{
    //декларации
    struct ICMPPACKET outPacket;                       //исходящая датаграмма
    struct ICMPINPACKET inPacket;                      //входящая датаграмма
    struct sockaddr_in sourceAddr;                     //адрес отправителя
    socklen_t adrSize = sizeof(sourceAddr);     //размер структуры адреса
    
    printf(" *Процедура oneTrace\n");
    
    setupOutPacket(&outPacket, ttl);
    
    setsockopt(rawSocket, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    
    if (sendto(rawSocket, (void *)&outPacket, sizeof(outPacket), 0, (struct sockaddr *)destAddr, sizeof(destAddr)) == -1)  //посылаем
    {
        if (errno == ENETUNREACH || errno == EACCES || errno == ENETDOWN || errno == EHOSTDOWN)
            serveError();
            return -1;
    }
    
    
    if (recvfrom(rawSocket, (void *)&inPacket, sizeof(inPacket), 0, (struct sockaddr *)&sourceAddr, &adrSize) == -1)       //получаем
    {
        if (errno == ENETUNREACH || errno == EACCES || errno == ENETDOWN || errno == EHOSTDOWN)
            serveError();
        return -1;
    }
    
    printf("IN PACKET: type: %i, adress: %s \n", inPacket.icmpRequest.header.type, inet_ntoa(*(struct in_addr *)&inPacket.ipHeader.sourceIP));         //отладочная информация
    
    return inPacket.icmpRequest.header.type;
}

//процедура трассировки до конечног узла
PROCEDURE void traceAll(int rawSocket, struct sockaddr_in *destAddr, int count)
{
    //декларации
    int result = -1;                                    //хранение кода ICMP результата
    
    printf(" *Процедура traceAll\n");

    for (int i = 1; result != 3 && result != 0 && i < 30; i++)  //30 прыжков максимум
    {
        result = oneTrace(rawSocket, destAddr, i);
        if (result == -1)
        {
            printf("* * *\n");
            i++;
        }
    }
}

//ТЕЛО ПРОГРАММЫ
int main(int argc, const char * argv[]) {
    //декларации
    struct sockaddr_in destAddr;       //ip адрес узла
    int rawSocket;                     //дескриптор сокета
    
    switch (mystart(&destAddr, argc, argv, &rawSocket)) {
        case 1:
            traceAll(rawSocket, &destAddr, 30);
            break;
        case 2:
            traceAll(rawSocket, &destAddr, 30);
        case 0:
            serveError();
            break;
    }
    myfinish();
    return 0;
}
