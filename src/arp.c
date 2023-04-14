#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = constswap16(ARP_HW_ETHER),
    .pro_type16 = constswap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // TO-DO
    // init txbuf with header
    // sizeof(arp_pkt_t) is 28
    buf_init(&txbuf, sizeof(arp_pkt_t));
    // get header from txbuf
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    // copy arp_init_pkt to arp_pkt
    memcpy(arp_pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    // set operation to request
    arp_pkt->opcode16 = constswap16(ARP_REQUEST);
    // set target ip
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    // send arp request
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // TO-DO
    // init txbuf with header
    // sizeof(arp_pkt_t) is 28
    buf_init(&txbuf, sizeof(arp_pkt_t));
    // get header from txbuf
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    // copy arp_init_pkt to arp_pkt
    memcpy(arp_pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    // set operation to response
    arp_pkt->opcode16 = constswap16(ARP_REPLY);
    // set target ip
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    // set target mac
    memcpy(arp_pkt->target_mac, target_mac, NET_MAC_LEN);
    // send arp response
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // if lenth of arp_buf is less than ARP's header, return
    if(buf->len<sizeof(arp_pkt_t)){
        return;
    }
    // check arp header
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;
    // if arp header is not valid, return
    if (constswap16(arp_pkt->hw_type16) != ARP_HW_ETHER ||
        constswap16(arp_pkt->pro_type16) != NET_PROTOCOL_IP ||
        arp_pkt->hw_len != NET_MAC_LEN || arp_pkt->pro_len != NET_IP_LEN ||
        (constswap16(arp_pkt->opcode16) != ARP_REPLY && constswap16(arp_pkt->opcode16) != ARP_REQUEST))
    {
        return;
    }
    // update arp_table
    map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);
    
    // cheak if arp_buf has the packet
    buf_t *buf2 = map_get(&arp_buf, arp_pkt->sender_ip);
    if (buf2 != NULL)
    {
        // if has, send the packet
        ethernet_out(buf2, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        // remove the packet from arp_buf
        map_delete(&arp_buf, arp_pkt->sender_ip);
        return;
    }
    // check if the packet is a request and the target is me
    if (constswap16(arp_pkt->opcode16) == ARP_REQUEST &&
        // compare target_ip with {192.168.1.1}
        memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0
        )
    {
        // if yes, send arp response
        arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
    }

}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // TO-DO
    // search for mac in arp_table with ip
    uint8_t *mac = map_get(&arp_table, ip);
    if (mac != NULL)
    {
        // if found, send the packet
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
        return;
    }
    // search if arp_buf is taken
    if (map_get(&arp_buf, ip) != NULL)
    {
        // if taken, return
        return;
    }
    // if not found, add the packet to arp_buf
    map_set(&arp_buf, ip, buf);
    // send arp request
    arp_req(ip);
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}