#include <assert.h>
#include "map.h"
#include "tcp.h"
#include "ip.h"

void my_reset_tcp(tcp_connect_t *connect, uint32_t get_seq);
void my_close_tcp(tcp_connect_t *connect);

static void panic(const char* msg, int line) {
    printf("panic %s! at line %d\n", msg, line);
    assert(0);
}

static void display_flags(tcp_flags_t flags) {
    printf("flags:%s%s%s%s%s%s%s%s\n",
        flags.cwr ? " cwr" : "",
        flags.ece ? " ece" : "",
        flags.urg ? " urg" : "",
        flags.ack ? " ack" : "",
        flags.psh ? " psh" : "",
        flags.rst ? " rst" : "",
        flags.syn ? " syn" : "",
        flags.fin ? " fin" : ""
    );
}

// dst-port -> handler
static map_t tcp_table; //tcp_table里面放了一个dst_port的回调函数

// tcp_key_t[IP, src port, dst port] -> tcp_connect_t

/* Connect_table放置了一堆TCP连接，
    KEY为[IP，src port，dst port], 即tcp_key_t，VALUE为tcp_connect_t。
*/
static map_t connect_table; 

/**
 * @brief 生成一个用于 connect_table 的 key
 *
 * @param ip
 * @param src_port
 * @param dst_port
 * @return tcp_key_t
 */
static tcp_key_t new_tcp_key(uint8_t ip[NET_IP_LEN], uint16_t src_port, uint16_t dst_port) {
    tcp_key_t key;
    memcpy(key.ip, ip, NET_IP_LEN);
    key.src_port = src_port;
    key.dst_port = dst_port;
    return key;
}

/**
 * @brief 初始化tcp在静态区的map
 *        供应用层使用
 *
 */
void tcp_init() {
    map_init(&tcp_table, sizeof(uint16_t), sizeof(tcp_handler_t), 0, 0, NULL);
    map_init(&connect_table, sizeof(tcp_key_t), sizeof(tcp_connect_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_TCP, tcp_in);
}

/**
 * @brief 向 port 注册一个 TCP 连接以及关联的回调函数
 *        供应用层使用
 *
 * @param port
 * @param handler
 * @return int
 */
int tcp_open(uint16_t port, tcp_handler_t handler) {
    printf("tcp open\n");
    return map_set(&tcp_table, &port, &handler);
}

/**
 * @brief 完成了缓存分配工作，状态也会切换为TCP_SYN_RCVD
 *        rx_buf和tx_buf在触及边界时会把数据重新移动到头部，防止溢出。
 *
 * @param connect
 */
static void init_tcp_connect_rcvd(tcp_connect_t* connect) {
    if (connect->state == TCP_LISTEN) {
        connect->rx_buf = malloc(sizeof(buf_t));
        connect->tx_buf = malloc(sizeof(buf_t));
    }
    buf_init(connect->rx_buf, 0);
    buf_init(connect->tx_buf, 0);
    connect->state = TCP_SYN_RCVD;
}

/**
 * @brief 释放TCP连接，这会释放分配的空间，并把状态变回LISTEN。
 *        一般这个后边都会跟个map_delete(&connect_table, &key)把状态变回CLOSED
 *
 * @param connect
 */
static void release_tcp_connect(tcp_connect_t* connect) {
    if (connect->state == TCP_LISTEN)
        return;
    free(connect->rx_buf);
    free(connect->tx_buf);
    connect->state = TCP_LISTEN;
}

static uint16_t tcp_checksum(buf_t* buf, uint8_t* src_ip, uint8_t* dst_ip) {
    uint16_t len = (uint16_t)buf->len;
    tcp_peso_hdr_t* peso_hdr = (tcp_peso_hdr_t*)(buf->data - sizeof(tcp_peso_hdr_t));
    tcp_peso_hdr_t pre; //暂存被覆盖的IP头
    memcpy(&pre, peso_hdr, sizeof(tcp_peso_hdr_t));
    memcpy(peso_hdr->src_ip, src_ip, NET_IP_LEN);
    memcpy(peso_hdr->dst_ip, dst_ip, NET_IP_LEN);
    peso_hdr->placeholder = 0;
    peso_hdr->protocol = NET_PROTOCOL_TCP;
    peso_hdr->total_len16 = swap16(len);
    uint16_t checksum = checksum16((uint16_t*)peso_hdr, len + sizeof(tcp_peso_hdr_t));
    memcpy(peso_hdr, &pre, sizeof(tcp_peso_hdr_t));
    return checksum;
}

static _Thread_local uint16_t delete_port;

/**
 * @brief tcp_close使用这个函数来查找可以关闭的连接，使用thread-local变量delete_port传递端口号。
 *
 * @param key,value,timestamp
 */
static void close_port_fn(void* key, void* value, time_t* timestamp) {
    tcp_key_t* tcp_key = key;
    tcp_connect_t* connect = value;
    if (tcp_key->dst_port == delete_port) {
        release_tcp_connect(connect);
    }
}

/**
 * @brief 关闭 port 上的 TCP 连接
 *        供应用层使用
 *
 * @param port
 */
void tcp_close(uint16_t port) {
    delete_port = port;
    map_foreach(&connect_table, close_port_fn);
    map_delete(&tcp_table, &port);
}

/**
 * @brief 从 buf 中读取数据到 connect->rx_buf
 *
 * @param connect
 * @param buf
 * @return uint16_t 字节数
 */
static uint16_t tcp_read_from_buf(tcp_connect_t* connect, buf_t* buf) {
    uint8_t* dst = connect->rx_buf->data + connect->rx_buf->len;
    buf_add_padding(connect->rx_buf, buf->len);
    memcpy(dst, buf->data, buf->len);
    connect->ack += buf->len;
    return buf->len;
}

/**
 * @brief 把connect内tx_buf的数据写入到buf里面供tcp_send使用，buf原来的内容会无效。
 *
 * @param connect
 * @param buf
 * @return uint16_t 字节数
 */
static uint16_t tcp_write_to_buf(tcp_connect_t* connect, buf_t* buf) {
    uint16_t sent = connect->next_seq - connect->unack_seq;
    uint16_t size = min32(connect->tx_buf->len - sent, connect->remote_win);
    buf_init(buf, size);
    memcpy(buf->data, connect->tx_buf->data + sent, size);
    connect->next_seq += size;
    return size;
}

/**
 * @brief 发送TCP包, seq_number32 = connect->next_seq - buf->len
 *        buf里的数据将作为负载，加上tcp头发送出去。如果flags包含syn或fin，seq会递增。
 *
 * @param buf
 * @param connect
 * @param flags
 */
static void tcp_send(buf_t* buf, tcp_connect_t* connect, tcp_flags_t flags) {
    // printf("<< tcp send >> sz=%zu\n", buf->len);
    display_flags(flags);
    size_t prev_len = buf->len;
    buf_add_header(buf, sizeof(tcp_hdr_t));
    tcp_hdr_t* hdr = (tcp_hdr_t*)buf->data;
    hdr->src_port16 = swap16(connect->local_port);
    hdr->dst_port16 = swap16(connect->remote_port);
    hdr->seq_number32 = swap32(connect->next_seq - prev_len);
    hdr->ack_number32 = swap32(connect->ack);
    hdr->data_offset = sizeof(tcp_hdr_t) / sizeof(uint32_t);
    hdr->reserved = 0;
    hdr->flags = flags;
    hdr->window_size16 = swap16(connect->remote_win);
    hdr->chunksum16 = 0;
    hdr->urgent_pointer16 = 0;
    hdr->chunksum16 = tcp_checksum(buf, connect->ip, net_if_ip);
    ip_out(buf, connect->ip, NET_PROTOCOL_TCP);
    if (flags.syn || flags.fin) {
        connect->next_seq += 1;
    }
}

/**
 * @brief 从外部关闭一个TCP连接, 会发送剩余数据
 *        供应用层使用
 *
 * @param connect
 */
void tcp_connect_close(tcp_connect_t* connect) {
    if (connect->state == TCP_ESTABLISHED) {
        tcp_write_to_buf(connect, &txbuf);
        tcp_send(&txbuf, connect, tcp_flags_ack_fin);
        connect->state = TCP_FIN_WAIT_1;
        return;
    }
    tcp_key_t key = new_tcp_key(connect->ip, connect->remote_port, connect->local_port);
    release_tcp_connect(connect);
    map_delete(&connect_table, &key);
}

/**
 * @brief 从 connect 中读取数据到 buf，返回成功的字节数。
 *        供应用层使用
 *
 * @param connect
 * @param data
 * @param len
 * @return size_t
 */
size_t tcp_connect_read(tcp_connect_t* connect, uint8_t* data, size_t len) {
    buf_t* rx_buf = connect->rx_buf;
    size_t size = min32(rx_buf->len, len);
    memcpy(data, rx_buf->data, size);
    if (buf_remove_header(rx_buf, size) != 0) {
        memmove(rx_buf->payload, rx_buf->data, rx_buf->len);
        rx_buf->data = rx_buf->payload;
    }
    return size;
}

/**
 * @brief 往connect的tx_buf里面写东西，返回成功的字节数，这里要判断窗口够不够，否则图片显示不全。
 *        供应用层使用
 *
 * @param connect
 * @param data
 * @param len
 */
size_t tcp_connect_write(tcp_connect_t* connect, const uint8_t* data, size_t len) {
    // printf("tcp_connect_write size: %zu\n", len);
    buf_t* tx_buf = connect->tx_buf;

    uint8_t* dst = tx_buf->data + tx_buf->len;
    size_t size = min32(&tx_buf->payload[BUF_MAX_LEN] - dst, len);

    if (connect->next_seq - connect->unack_seq + len >= connect->remote_win) {
        return 0;
    }
    if (buf_add_padding(tx_buf, size) != 0) {
        memmove(tx_buf->payload, tx_buf->data, tx_buf->len);
        tx_buf->data = tx_buf->payload;
        if (tcp_write_to_buf(connect, &txbuf)) {
            tcp_send(&txbuf, connect, tcp_flags_ack);
        }
        return 0;
    }
    memcpy(dst, data, size);
    return size;
}

/**
 * @brief 服务器端TCP收包
 *
 * @param buf
 * @param src_ip
 */
void tcp_in(buf_t* buf, uint8_t* src_ip) {
    printf("<<< tcp_in >>>\n");

    /*
    1、大小检查，检查buf长度是否小于tcp头部，如果是，则丢弃
    */

   // TODO
   if (buf->len < sizeof(tcp_hdr_t)) {
       return;
    }

    /*
    2、检查checksum字段，如果checksum出错，则丢弃
    */

   // TODO
    tcp_hdr_t* hdr = (tcp_hdr_t*)buf->data;
    uint16_t checksum = hdr->chunksum16;
    hdr->chunksum16 = 0;
    if (checksum != tcp_checksum(buf, src_ip, net_if_ip)) {
        return;
    }
    hdr->chunksum16 = checksum;


    /*
    3、从tcp头部字段中获取source port、destination port、
    sequence number、acknowledge number、flags，注意大小端转换
    */

   // TODO
    uint16_t src_port = swap16(hdr->src_port16);
    uint16_t dst_port = swap16(hdr->dst_port16);
    uint32_t seq_num = swap32(hdr->seq_number32);
    uint32_t ack_num = swap32(hdr->ack_number32);
    tcp_flags_t flags = hdr->flags;


    /*
    4、调用map_get函数，根据destination port查找对应的handler函数
    */

   // TODO
    tcp_handler_t *tcp_handler = map_get(&tcp_table, &dst_port);
    if (tcp_handler == NULL) {
        return;
    }

    /*
    5、调用new_tcp_key函数，根据通信五元组中的源IP地址、目标IP地址、目标端口号确定一个tcp链接key
    */

   // TODO
    //** ? **
    tcp_key_t key = new_tcp_key(src_ip, src_port, dst_port);

    /*
    6、调用map_get函数，根据key查找一个tcp_connect_t* connect，
    如果没有找到，则调用map_set建立新的链接，并设置为CONNECT_LISTEN状态，然后调用mag_get获取到该链接。
    */

    // TODO
    tcp_connect_t *connect = map_get(&connect_table, &key);
    if (connect == NULL) {
        connect = (tcp_connect_t *)malloc(sizeof(tcp_connect_t));
        connect->state = TCP_LISTEN;
        map_set(&connect_table, &key, connect);
    }
    // why need map_get again??? 🤯 the action of map is confusing
    connect = map_get(&connect_table, &key);

    /*
    7、从TCP头部字段中获取对方的窗口大小，注意大小端转换
    */

   // TODO
    uint16_t win_size = swap16(hdr->window_size16);

    /*
    8、如果为TCP_LISTEN状态，则需要完成如下功能：
        （1）如果收到的flag带有rst，则close_tcp关闭tcp链接
        （2）如果收到的flag不是syn，则reset_tcp复位通知。因为收到的第一个包必须是syn
        （3）调用init_tcp_connect_rcvd函数，初始化connect，将状态设为TCP_SYN_RCVD
        （4）填充connect字段，包括
            local_port、remote_port、ip、
            unack_seq（设为随机值）、由于是对syn的ack应答包，next_seq与unack_seq一致
            ack设为对方的sequence number+1
            设置remote_win为对方的窗口大小，注意大小端转换
        （5）调用buf_init初始化txbuf
        （6）调用tcp_send将txbuf发送出去，也就是回复一个tcp_flags_ack_syn（SYN+ACK）报文
        （7）处理结束，返回。
    */

   // TODO
    if (connect->state == TCP_LISTEN) {
        if (flags.rst == 1) {
            my_close_tcp(connect);
            return;
        }
        if (flags.syn==0) {
            my_reset_tcp(connect, seq_num);
            return;
        }
        init_tcp_connect_rcvd(connect);
        connect->local_port = dst_port;
        connect->remote_port = src_port;
        memcpy(connect->ip, src_ip, NET_IP_LEN);
        time_t t;
        srand((unsigned) time(&t));
        connect->unack_seq = rand();
        connect->next_seq = connect->unack_seq;
        connect->ack = seq_num + 1;
        connect->remote_win = win_size;
        // buf_init(connect->tx_buf, 0);
        // tcp_send(connect->tx_buf, connect, tcp_flags_ack_syn);
        buf_init(&txbuf, 0);
        tcp_send(&txbuf, connect, tcp_flags_ack_syn);
        return;
    }


    /* 
    9、检查接收到的sequence number，如果与ack序号不一致,则reset_tcp复位通知。
    */

   // TODO
    if (seq_num != connect->ack) {
        my_reset_tcp(connect, seq_num);
        return;
    }

    /* 
    10、检查flags是否有rst标志，如果有，则close_tcp连接重置
    */

   // TODO
    if (flags.rst == 1) {
        my_close_tcp(connect);
        return;
    }

    /*
    11、序号相同时的处理，调用buf_remove_header去除头部后剩下的都是数据
    */

   // TODO
    buf_remove_header(buf, sizeof(tcp_hdr_t));

    /* 状态转换
    */
    switch (connect->state) {
    case TCP_LISTEN:
        panic("switch TCP_LISTEN", __LINE__);
        break;

    case TCP_SYN_RCVD:

//         /*
//         12、在RCVD状态，如果收到的包没有ack flag，则不做任何处理
//         */  

//        // TODO
        // 等待三次握手
        if (flags.ack == 0) {
            return;
        }

//         /*
//         13、如果是ack包，需要完成如下功能：
//             （1）将unack_seq +1
//             （2）将状态转成ESTABLISHED
//             （3）调用回调函数，完成三次握手，进入连接状态TCP_CONN_CONNECTED。
//         */
        
//         // TODO
        //完成三次握手
        connect->unack_seq++;
        connect->state = TCP_ESTABLISHED;
        (*tcp_handler)(connect, TCP_CONN_CONNECTED);
        break;

    case TCP_ESTABLISHED:

//         /*
//         14、如果收到的包没有ack且没有fin这两个标志，则不做任何处理
//         */

//        // TODO
        if (flags.ack == 0 && flags.fin == 0) {
            return;
        }


//         /*
//         15、这里先处理ACK的值，
//             如果是ack包，
//             且unack_seq小于sequence number（说明有部分数据被对端接收确认了，否则可能是之前重发的ack，可以不处理），
//             且next_seq大于sequence number
//             则调用buf_remove_header函数，去掉被对端接收确认的部分数据，并更新unack_seq值
            
//         */

//        // TODO
        if (flags.ack==1 && connect->unack_seq < seq_num && connect->next_seq > seq_num) {
            buf_remove_header(connect->tx_buf, seq_num - connect->unack_seq);
            connect->unack_seq = seq_num;
        }


//         /*
//         16、然后接收数据
//             调用tcp_read_from_buf函数，把buf放入rx_buf中
//         */

//        // TODO
        tcp_read_from_buf(connect, buf);

//         /*
//         17、再然后，根据当前的标志位进一步处理
//             （1）首先调用buf_init初始化txbuf
//             （2）判断是否收到关闭请求（FIN），如果是，将状态改为TCP_LAST_ACK，ack +1，再发送一个ACK + FIN包，并退出，
//                 这样就无需进入CLOSE_WAIT，直接等待对方的ACK
//             （3）如果不是FIN，则看看是否有数据，如果有，则发ACK相应，并调用handler回调函数进行处理
//             （4）调用tcp_write_to_buf函数，看看是否有数据需要发送，如果有，同时发数据和ACK
//             （5）没有收到数据，可能对方只发一个ACK，可以不响应

//         */

//        // TODO
        buf_init(&txbuf, 0);
        if (flags.fin == 1) {
            //收到第一次挥手，进入TCP_LAST_ACK状态
            connect->state = TCP_LAST_ACK;
            connect->ack++;
            tcp_send(connect->tx_buf, connect, tcp_flags_ack_fin);
            return;
        }
        if (buf->len > 0) {
            (*tcp_handler)(connect, TCP_CONN_DATA_RECV);
            tcp_write_to_buf(connect, &txbuf);
            tcp_send(&txbuf, connect, tcp_flags_ack);
        }else
            tcp_send(&txbuf, connect, tcp_flags_ack);


        break;

    case TCP_CLOSE_WAIT:
        panic("switch TCP_CLOSE_WAIT", __LINE__);
        break;

    case TCP_FIN_WAIT_1:

//         /*
//         18、如果收到FIN && ACK，则close_tcp直接关闭TCP
//             如果只收到ACK，则将状态转为TCP_FIN_WAIT_2
//         */

//        // TODO
        if (flags.fin ==1 && flags.ack == 1) {
            my_close_tcp(connect);
            return;
        }
        if (flags.ack == 1 && flags.fin == 0) {
            connect->state = TCP_FIN_WAIT_2;
        }
        break;

    case TCP_FIN_WAIT_2:
//         /*
//         19、如果不是FIN，则不做处理
//             如果是，则将ACK +1，调用buf_init初始化txbuf，调用tcp_send发送一个ACK数据包，再close_tcp关闭TCP
//         */

//        // TODO
        if (flags.fin == 0) {
            return;
        }
        connect->ack++;
        buf_init(&txbuf, 0);
        tcp_send(&txbuf, connect, tcp_flags_ack);
        my_close_tcp(connect);
        break;

    case TCP_LAST_ACK:
//         /*
//         20、如果不是ACK，则不做处理
//             如果是，则调用handler函数，进入TCP_CONN_CLOSED状态，，再close_tcp关闭TCP
//         */

//        // TODO
        if (flags.ack == 0) {
            return;
        }
        (*tcp_handler)(connect, TCP_CONN_CLOSED);
        my_close_tcp(connect);
        break;

    default:
        panic("connect->state", __LINE__);
        break;
    }
    return;
}
/**
 * @brief tcp连接关闭
 * 
 * @param connect 
 * @param get_seq
 * @param type 1:changge seqence and reset 0:ack and syn
 * 
 * @return void
 */
void my_reset_tcp(tcp_connect_t *connect, uint32_t get_seq)
{
    printf("!!! reset tcp !!!\n");
    connect->next_seq = 0;
    connect->ack = get_seq + 1;
    buf_init(&txbuf, 0);
    tcp_send(&txbuf, connect, tcp_flags_ack_rst);
}
void my_close_tcp(tcp_connect_t *connect)
{
    printf("!!! close tcp !!!\n");
    tcp_connect_close(connect);
    return;
}
