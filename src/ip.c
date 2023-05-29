#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // if length of buffer is less than IP header, then throw it
    if (buf->len < sizeof(ip_hdr_t))
    {
        return;
    }
    // check header about ip version and length
    ip_hdr_t *ip_head = (ip_hdr_t *)buf->data;
    if (ip_head->version != 4 || swap16(ip_head->total_len16) > buf->len)
    {
        return;
    }
    // check checksum
    uint16_t checksum = ip_head->hdr_checksum16;
    ip_head->hdr_checksum16 = 0;
    if (checksum != checksum16((uint16_t*)(buf->data), sizeof(ip_hdr_t)))
    {
        return;
    }
    ip_head->hdr_checksum16 = checksum;
    // check ip address as array
    if (memcmp(ip_head->dst_ip, net_if_ip, 4) != 0)
    {
        return;
    }
    // if size of buffer is larger than IP header's total_len16, then remove padding
    if (buf->len > swap16(ip_head->total_len16))
    {
        buf_remove_padding(buf, buf->len - swap16(ip_head->total_len16));
    }
    

    // if protocol is unknown, then unreachable
    if (ip_head->protocol == NET_PROTOCOL_IP || ip_head->protocol == NET_PROTOCOL_ARP ||
        ip_head->protocol == NET_PROTOCOL_UDP || ip_head->protocol == NET_PROTOCOL_ICMP ||
        ip_head->protocol == NET_PROTOCOL_TCP)
    {
        // remove ip header
        buf_remove_header(buf, sizeof(ip_hdr_t));
        net_in(buf, ip_head->protocol, ip_head->src_ip);
    }
    else
    {
        icmp_unreachable(buf, ip_head->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
    
}

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    // add header
    buf_add_header(buf, sizeof(ip_hdr_t));
    // enter ip header
    ip_hdr_t *ip_head = (ip_hdr_t *)buf->data;
    // set ip version and header length
    ip_head->version = 4;
    ip_head->hdr_len = sizeof(ip_hdr_t) / 4;
    // set tos
    ip_head->tos = 0;
    // set ip total length
    ip_head->total_len16 = swap16(buf->len);
    // set ip id
    ip_head->id16 = swap16(id);
    // set ip offset
    ip_head->flags_fragment16 = 0;
    ip_head->flags_fragment16 = offset;
    // set ip mf
    if (mf)
    {
        ip_head->flags_fragment16 |= IP_MORE_FRAGMENT;
    }
    ip_head->flags_fragment16 = swap16(ip_head->flags_fragment16);
    // set ip ttl
    ip_head->ttl = IP_DEFALUT_TTL;
    // set ip protocol
    ip_head->protocol = protocol;
    // set ip src ip
    memcpy(&ip_head->src_ip, &net_if_ip, sizeof(net_if_ip));
    // set ip dst ip
    memcpy(&ip_head->dst_ip, ip, sizeof(net_if_ip));
    // set ip checksum
    ip_head->hdr_checksum16 = 0;
    ip_head->hdr_checksum16 = checksum16((uint16_t*)(buf->data), sizeof(ip_hdr_t));
    // send ip packet
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    static int id = 0;
    // if length of buffer is larger than MTU (1500)
    if (buf->len <= 1500 - sizeof(ip_hdr_t))
    {
        ip_fragment_out(buf, ip, protocol, id, 0, 0);
        id++;
        return;
    }
    // cut buffer and send fragment
    int data_per_packet = (1500 - sizeof(ip_hdr_t)) / 8 * 8;
    int cut_num = (buf->len + data_per_packet - 1) / data_per_packet;
    for (size_t i = 0; i < cut_num - 1; i++)
    {
        buf_t *term_buf = (buf_t *)malloc(sizeof(buf_t));
        buf_init(term_buf, data_per_packet);
        // copy data from buf
        memcpy(term_buf->data, buf->data + i * data_per_packet, data_per_packet);
        ip_fragment_out(term_buf, ip, protocol, id, i * data_per_packet/8, 1);
    }
    buf_t *term_buf = (buf_t *)malloc(sizeof(buf_t));
    buf_init(term_buf, buf->len % data_per_packet);
    // copy data from buf
    memcpy(term_buf->data, buf->data + (cut_num - 1) * data_per_packet, buf->len % data_per_packet);
    ip_fragment_out(term_buf, ip, protocol, id , (cut_num - 1) * data_per_packet/8, 0);
    id++;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}