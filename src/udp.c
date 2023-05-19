#include "udp.h"
#include "ip.h"
#include "icmp.h"

/**
 * @brief udp处理程序表
 * 
 */
map_t udp_table;

/**
 * @brief udp伪校验和计算
 * 
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dst_ip 目的ip地址
 * @return uint16_t 伪校验和
 */
static uint16_t udp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip)
{
    // TO-DO
    // add fake header
    buf_add_header(buf, sizeof(udp_peso_hdr_t));
    udp_peso_hdr_t *udp_peso_head = (udp_peso_hdr_t *)buf->data;
    // backup data in head
    ip_hdr_t udp_peso_head_backup;
    memcpy(&udp_peso_head_backup, udp_peso_head, sizeof(udp_peso_hdr_t));
    // enter peso head
    memcpy(udp_peso_head->src_ip, src_ip, sizeof(udp_peso_head->src_ip));
    memcpy(udp_peso_head->dst_ip, dst_ip, sizeof(udp_peso_head->dst_ip));
    udp_peso_head->placeholder = 0;
    udp_peso_head->protocol = NET_PROTOCOL_UDP;
    udp_peso_head->total_len16 = swap16(buf->len- sizeof(udp_peso_hdr_t));
    
    // calculate checksum
    // if (buf->len % 2 == 1){
    //     buf_add_padding(buf, 1);
    // }
    uint16_t checksum = checksum16((uint16_t *)buf->data, buf->len);
    // restore data in head
    memcpy(udp_peso_head, &udp_peso_head_backup, sizeof(udp_peso_hdr_t));
    // remove fake header
    buf_remove_header(buf, sizeof(udp_peso_hdr_t));

    return checksum;
}

/**
 * @brief 处理一个收到的udp数据包
 * 
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    // check length , throw if length is less than udp header or udp header's total_len16 is larger than buffer's length
    udp_hdr_t *udp_head = (udp_hdr_t *)buf->data;
    if (buf->len < sizeof(udp_hdr_t) || swap16(udp_head->total_len16) > buf->len)
    {
        return;
    }
    // check checksum
    uint16_t checksum = udp_head->checksum16;
    udp_head->checksum16 = 0;
    if (checksum != udp_checksum(buf, src_ip, net_if_ip))
    {
        return;
    }
    udp_head->checksum16 = checksum;
    // search in udp table
    udp_head->dst_port16 = swap16(udp_head->dst_port16);
    udp_handler_t* udp_handler = map_get(&udp_table, &(udp_head->dst_port16));
    udp_head->dst_port16 = swap16(udp_head->dst_port16);
    if ( udp_handler != NULL)
    {
        // remove udp header
        buf_remove_header(buf, sizeof(udp_hdr_t));
        // call handler
        (*udp_handler)(buf->data, buf->len, src_ip, swap16(udp_head->src_port16));
    }
    else
    {
        // if port is not found, then unreachable
        buf_add_header(buf, sizeof(ip_hdr_t));
        ip_hdr_t *ip_head = (ip_hdr_t *)buf->data;
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    // TO-DO
    // add udp head to buf
    buf_add_header(buf, sizeof(udp_hdr_t));
    udp_hdr_t *udp_head = (udp_hdr_t *)buf->data;
    udp_head->src_port16 = swap16(src_port);
    udp_head->dst_port16 = swap16(dst_port);
    udp_head->total_len16 = swap16(buf->len);
    udp_head->checksum16 = 0;
    // calculate checksum
    udp_head->checksum16 = udp_checksum(buf, net_if_ip, dst_ip);
    // send ip packet
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 * 
 */
void udp_init()
{
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 * 
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 * 
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 * 
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}