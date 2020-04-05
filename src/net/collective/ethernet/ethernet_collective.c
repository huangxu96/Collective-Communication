/* 
 * This file is part of the Nautilus AeroKernel developed
 * by the Hobbes and V3VEE Projects with funding from the 
 * United States National  Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  The Hobbes Project is a collaboration
 * led by Sandia National Laboratories that includes several national 
 * laboratories and universities. You can find out more at:
 * http://www.v3vee.org  and
 * http://xstack.sandia.gov/hobbes
 *
 * Copyright (c) 2018, Peter Dinda <pdinda@northwestern.edu>
 * Copyright (c) 2018, The V3VEE Project  <http://www.v3vee.org> 
 *                     The Hobbes Project <http://xstack.sandia.gov/hobbes>
 * All rights reserved.
 *
 * Author: Peter Dinda <pdinda@northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "LICENSE.txt".
 */

#include <nautilus/nautilus.h>
#include <nautilus/list.h>
#include <nautilus/spinlock.h>
#include <nautilus/netdev.h>
#include <nautilus/scheduler.h>
#include <net/collective/ethernet/ethernet_collective.h>

#ifndef NAUT_CONFIG_DEBUG_NET_COLLECTIVE_ETHERNET
#undef DEBUG_PRINT
#define DEBUG_PRINT(fmt, args...) 
#endif

#define ERROR(fmt, args...) ERROR_PRINT("ether_col: " fmt, ##args)
#define DEBUG(fmt, args...) DEBUG_PRINT("ether_col: " fmt, ##args)
#define INFO(fmt, args...) INFO_PRINT("ether_col: " fmt, ##args)

// Fast L2 collective communication, currently just barriers and rings
// Also currently assumes no packet loss
// Also currently assumes synchrony barrier

// This is a work in progress

typedef enum {COLLECTIVE_IDLE=0, COLLECTIVE_GATHER, COLLECTIVE_SCATTER, COLLECTIVE_BCAST, COLLECTIVE_BARRIER, COLLECTIVE_RING} mode_t;
typedef enum {GATHER_IDLE=0, GATHER_UP, GATHER_DOWN} gather_state_t;
typedef enum {SCATTER_IDLE=0, SCATTER_UP, SCATTER_DOWN} scatter_state_t;
typedef enum {BCAST_IDLE=0, BCAST_UP, BCAST_DOWN} bcast_state_t;
typedef enum {BARRIER_IDLE=0, BARRIER_UP, BARRIER_DOWN} barrier_state_t;
typedef enum {RING_IDLE=0, RING_STATE_1, RING_STATE_2} ring_state_t;

// collective message types
#define COLLECTIVE_RING_STATE_1     0x1
#define COLLECTIVE_RING_STATE_2     0x2
#define COLLECTIVE_BARRIER_TYPE     0x3
#define COLLECTIVE_BCAST_TYPE       0x4
#define COLLECTIVE_SCATTER_TYPE     0x5
#define COLLECTIVE_GATHER_TYPE      0x6

#define REGEN_DELAY_NS 1000000000


struct nk_net_ethernet_collective {
    mode_t   current_mode;            // what operation we are handling
    int      timeout_flag;
    uint32_t      gen;

    // for gather operations
    gather_state_t gather_state;
    uint64_t data_count_in_packet;

    // for scatter and gather operations
    scatter_state_t scatter_state;
    void          *send_data;
    void          *recv_data;
    uint64_t      send_count;
    uint64_t      recv_count; // send count equals recv count
    // for bcast operations
    bcast_state_t bcast_state;
    void          *data;
    uint64_t      data_len;
    // varibels shared by mutiple functions
    uint32_t      root; // which node is the root node of opeartion. 
    uint32_t      data_size;
    // for barrier operations
    barrier_state_t barrier_state;
    uint32_t curlevel;
    uint32_t maxlevel;
    uint8_t *recv_buffer;
    
    // for ring operations
    ring_state_t ring_state;
    int          initiator;
    void        *token;
    uint64_t     token_len;


    // the network device to use - this is supplied by an ethernet agent
    // it must support the ethernet agent send/receive packet interface
    struct nk_net_dev                          *netdev;
    struct nk_net_dev_characteristics           netchar;

    //  general metadata for collective operations
    uint32_t   num_nodes;  // size of the collective
    uint32_t   my_node;    // my own index in the mac array (e.g., my rank)
    uint16_t   type;       // ethernet type to use for collective operations
    ethernet_mac_addr_t macs[0];    // members of the collective - extended as per number requested
};

static inline void encode_packet(nk_ethernet_packet_t *p, ethernet_mac_addr_t dest, ethernet_mac_addr_t src, uint16_t basetype, uint16_t subtype, void *data, uint16_t len)
{
    memcpy(p->header.dst,dest,6);
    memcpy(p->header.src,src,6);
    p->header.type = htons(basetype);

    memcpy(p->data,&subtype,2);
    memcpy(p->data+2,&len,2);
    memcpy(p->data+4,data,len);
    

    p->len = 14 + 2 + 2 + len;
}

// we match against basetype, and subtype, and return -1 if this is not a match
// otherwise we deconstruct the packet
// len is an i/o argument, in: size of buffer, out: amount of data
static inline int decode_packet(nk_ethernet_packet_t *p, ethernet_mac_addr_t dest, ethernet_mac_addr_t src, uint16_t basetype, uint16_t subtype, void *data, uint16_t *len)
{
    uint16_t t;
    
    t = ntohs(p->header.type);

    if (t!=basetype) {
	return -1;
    }

    memcpy(&t,p->data,2);

    if (t!=subtype) {
	return -1;
    }

    
    // matching packet, so decode
    memcpy(dest,p->header.dst,6);
    memcpy(src,p->header.src,6);

    memcpy(&t,p->data+2,2);

    if (t < *len) {
	*len = t;
    }
    
    memcpy(data, p->data+4, *len);
    p->len = *len + 14 + 2 +2;

    return 0;
}


// we match against basetype, and subtype, and return -1 if this is not a match
// otherwise we deconstruct the packet
// len is an i/o argument, in: size of buffer, out: amount of data
static inline int decode_packet_in_place(nk_ethernet_packet_t *p, ethernet_mac_addr_t **dest, ethernet_mac_addr_t **src, uint16_t basetype, uint16_t subtype, void **data, uint16_t *len)
{
    uint16_t t;
    
    t = ntohs(p->header.type);

    if (t!=basetype) {
	return -1;
    }

    memcpy(&t,p->data,2);

    if (t!=subtype) {
	return -1;
    }

    *dest = &p->header.dst;
    *src = &p->header.src;
    memcpy(&t,p->data+2,2);
    *len = t;
    *data = p->data+4;
    p->len = *len + 14 + 2 + 2;

    return 0;
}

static inline int decode_packet_in_place_test(nk_ethernet_packet_t *p, ethernet_mac_addr_t **dest, ethernet_mac_addr_t **src, uint16_t basetype, uint16_t *subtype, void **data, uint16_t *len)
{
    uint16_t t;
    
    t = ntohs(p->header.type);

    if (t!=basetype) {
	return -1;
    }

    memcpy(&t,p->data,2);

    *subtype = t;
    *dest = &p->header.dst;
    *src = &p->header.src;
    memcpy(&t,p->data+2,2);
    *len = t;
    *data = p->data+4;
    p->len = *len + 14 + 2 + 2;

    return 0;
}


typedef struct gather_data {
    uint8_t  dir; // 0=UP, 1=DOWN
    uint32_t level;
    uint32_t gen;
    uint32_t data_len;
    uint8_t  data [0]; // data in send_buf
} __packed gather_data_t;

typedef struct scatter_data {
    uint8_t  dir; // 0=UP, 1=DOWN
    uint32_t level;
    uint32_t gen;
    uint8_t  data [0]; // data in send_buf
} __packed scatter_data_t;

typedef struct bcast_data {
    uint8_t  dir; // 0=UP, 1=DOWN
    uint32_t level;
    uint32_t gen;
    uint8_t  data [0]; 
} __packed bcast_data_t;

typedef struct barrier_data {
    uint8_t  dir;  // 0=UP, 1=DOWN
    uint32_t level;
    uint32_t gen;
} __packed barrier_data_t;

uint32_t log2_ceil(uint32_t n)
{
    if (n == 1) return 0;
    return 32 - (__builtin_clz(n - 1));
}

uint32_t pow2(uint32_t n)
{
    if (n==0)
        return 1;
    return 2<<(n-1);
}

int nk_net_ethernet_collective_rank(struct nk_net_ethernet_collective *col, uint32_t* rank)
{
    *rank = col->my_node; 
    return 0;
}

static void collective_recv_callback(nk_net_dev_status_t status,
				  nk_ethernet_packet_t *packet,
				  void *state)
{
    struct nk_net_ethernet_collective *col = (struct nk_net_ethernet_collective *)state;
    uint16_t subtype;
    int rt;
    memcpy(&subtype,packet->data,2);
    switch (subtype){
        case COLLECTIVE_RING_STATE_1:
        case COLLECTIVE_RING_STATE_2:
            ring_recv_callback(status, packet, state);
            break;
        case COLLECTIVE_BARRIER_TYPE:
            barrier_recv_callback(status, packet, state);
            break;
        case COLLECTIVE_BCAST_TYPE:
            bcast_recv_callback(status, packet, state);
            break;
        case COLLECTIVE_SCATTER_TYPE:
            scatter_recv_callback(status, packet, state);
            break;
        case COLLECTIVE_GATHER_TYPE:
            gather_recv_callback(status, packet, state);
        default:
            break;
    }
    if (nk_net_ethernet_agent_device_receive_packet(col->netdev,
                            0,
                            NK_DEV_REQ_CALLBACK,
                            collective_recv_callback,
                            col)) {
        ERROR("Cannot initiate receive\n");
        return -1;
    }

}

int gather_send_packet(struct nk_net_ethernet_collective *col, uint8_t dir, uint32_t gen)
{
    DEBUG("Send packet of generation of %d\n", gen);
    DEBUG("barrier_send_packet, col->maxlevel=%d\n", col->maxlevel); 
    int i;
    nk_ethernet_packet_t *p = nk_net_ethernet_alloc_packet(-1);

    // Carefully calculate data_len, node with different max_level should send different length data.

    uint64_t data_len = col->data_size*col->data_count_in_packet;
    uint64_t buf_len = sizeof(gather_data_t)+data_len;
    char buf[buf_len];
    gather_data_t *b = (gather_data_t*)buf;
    nk_vc_printf("***data len: %d\n", data_len);
    b->dir = dir;
    b->level = col->maxlevel;
    b->gen = gen;
    b->data_len = data_len;
    nk_vc_printf("***1st val in packet col->send_data: %d\n", *(int*)col->send_data);
    memcpy(b->data, col->send_data, data_len);
    nk_vc_printf("***1st val in packet data: %d\n", *(int*)b->data);
    if (!p) {
            ERROR("Cannot allocate packet\n");
            return -1;
            }
    switch (dir){
        case 0:
            b->level = col->curlevel;
            if (col->my_node < pow2(col->maxlevel)) {
                return 0;
            }
            encode_packet(p,
                    col->macs[col->my_node - pow2(col->maxlevel)],
                    col->macs[col->my_node],
                    col->type,
                    COLLECTIVE_GATHER_TYPE,
                    b,
                    buf_len);
            if (nk_net_ethernet_agent_device_send_packet(col->netdev,
                        p,
                        NK_DEV_REQ_NONBLOCKING,
                        0,
                        0)) {
                    DEBUG("Initiator cannot launch packet\n");
                    return -1;
            }
            break;
        case 1: // send to root node
            encode_packet(p,
                col->macs[col->root], 
                col->macs[col->my_node],
                col->type,
                COLLECTIVE_GATHER_TYPE,
                b,
                buf_len);

            if (nk_net_ethernet_agent_device_send_packet(col->netdev,
                                        p,
                                        NK_DEV_REQ_NONBLOCKING,
                                        0, 0)) {
                    DEBUG("Initiator cannot launch packet\n");
                    return -1;
                }

            break;
        case 2: // retransmission req, just send packet down.
            for (i = col->maxlevel-1; i >= 0; i--)
            {
                b->level = i;
                int dst_index = col->my_node + pow2(i);
                DEBUG("my_node: %d, num_nodes: %d, dst: %d \n", col->my_node, col->num_nodes, dst_index);
                if (dst_index < col->num_nodes) {
                    encode_packet(p,
                            col->macs[col->my_node + pow2(i)],
                            col->macs[col->my_node],
                            col->type,
                            COLLECTIVE_GATHER_TYPE,
                            b,
                            buf_len);
                    
                    if (nk_net_ethernet_agent_device_send_packet(col->netdev,
                                    p,
                                    NK_DEV_REQ_NONBLOCKING,
                                    0, 0)) {
                        DEBUG("Initiator cannot launch packet\n");
                        return -1;
                    }
                }
            }
            break;
        default:
            break;
    }
        return 0;
}

static int gather_recv_callback(nk_net_dev_status_t status,
				  nk_ethernet_packet_t *packet,
				  void *state)
{
    struct nk_net_ethernet_collective *col = (struct nk_net_ethernet_collective *)state;
    ethernet_mac_addr_t *dest, *src;
    uint16_t subtype;
    uint32_t level;
    uint8_t dir;
    gather_data_t *gather = malloc(sizeof(gather_data_t));
    uint16_t gather_len;

    DEBUG("State :%d\n", col->gather_state);

    if (status!=NK_NET_DEV_STATUS_SUCCESS) {
        ERROR("Receive failure - the token will have to be regenerated\n");
        return -1;
    }

    if (decode_packet_in_place(packet,
			       &dest,
			       &src,
			       col->type,
			       COLLECTIVE_GATHER_TYPE,
			       (void **)(&gather),
			       &gather_len)) {
	    DEBUG("Packet does not match current operation\n");
        return -1; 
    }
    
    if(gather->gen > col->gen){
        DEBUG("We are behand, drop packet.\n");
        nk_net_ethernet_release_packet(packet);
        return -1; 
    }

    if(gather->gen < gather->gen || col->gather_state == GATHER_IDLE){
        DEBUG("Got gather packet for wrong generation, just go through it, gather->gen: %02d, col->gen: %02d\n", gather->gen, col->gen);
        if(gather->dir == 0){
            if(col->my_node == 0){ // if we are at top of tree, just change it into down dierction.
                gather_send_packet(col, 1, gather->gen);
            }
            else{
                gather_send_packet(col, 0, gather->gen);
            }
        }
        else if (gather->dir == 2){
            DEBUG("Got retransmission request!\n");
            // To Do:
            gather_send_packet(col, 0, gather->gen);
            //gather_send_packet(col, gather->dir, gather->gen);
        }
        return 1;
    }

    if (memcmp(dest, col->macs[col->my_node], 6) !=0) {
        DEBUG("Discarding gather packet for wrong destination, dest: %02d, my macs: %02d\n", (*dest)[5], col->macs[col->my_node][5]);
        nk_net_ethernet_release_packet(packet);
        return -1;
    }
    // Depending on difference between dest and src to decide where the received data should be put. 
    uint8_t diff = src[5] - dest[5]; 
    nk_vc_printf("***1st val in gather data: %d\n", *(int*)gather->data);
    // we assume all nodes send same count data, otherwise it will be so complicated.
    memcpy(col->send_data+diff*col->data_size*col->send_count, gather->data, gather->data_len);

    if (col->gather_state == GATHER_UP) {
	    if (gather->dir!=0) {
	        DEBUG("Discarding gather packet for wrong direction...\n");
	        nk_net_ethernet_release_packet(packet);
	        return -1;
        }

    	DEBUG("gather_level: %d, curlevel: %d, maxlevel: %d\n", gather->level, col->curlevel, col->maxlevel);
	    
        if (gather->level < col->curlevel) {
	        DEBUG("Discarding gather packet smaller than curlevel...\n");
	        nk_net_ethernet_release_packet(packet);
	        return -1;
        }

        col->recv_buffer[gather->level] = 1;
        
        while(col->curlevel < col->maxlevel && col->recv_buffer[col->curlevel] == 1) {
            col->curlevel++;
        }

        if (col->my_node == 0 && col->curlevel == col->maxlevel) {
	        // We are at the top of the tree and we should send packet to root
            if (gather_send_packet(col,1,col->gen)) {
                ERROR("Send packet down error.\n");
                return -1;
            }
        } 
        if (col->my_node != col->root && col->maxlevel == col->curlevel){
            // Every nodes except root becomes IDLE
            gather_send_packet(col,0,col->gen);
            memset(col->recv_buffer, 0, col->maxlevel * sizeof(uint8_t));
            __sync_lock_test_and_set(&col->gather_state, GATHER_IDLE); 
            __sync_lock_test_and_set(&col->current_mode, COLLECTIVE_IDLE);
        }
        if (col->my_node == col->root && col->maxlevel == col->curlevel ){ 
            // Root node becomes DOWN to wait packet from 0 node
            __sync_lock_test_and_set(&col->gather_state, GATHER_DOWN);   
        }
        return 0; 
    }

    if (col->gather_state == GATHER_DOWN) {
	    if (gather->dir != 1) {
	        DEBUG("Discarding gather packet for wrong direction...\n");
	        nk_net_ethernet_release_packet(packet);
	        return -1;
        }
        
        memcpy(col->recv_data, gather->data, col->data_size*col->recv_count);

        __sync_lock_test_and_set(&col->gather_state, GATHER_IDLE); 
        __sync_lock_test_and_set(&col->current_mode, COLLECTIVE_IDLE);
        return 0;
    }

}

// Currently, we assume all nodes send same count of data
nk_net_ethernet_collective_gather(void *send_data,
    uint64_t send_count, 
    uint32_t data_size,
    void *recv_data, 
    uint64_t recv_count,
    uint32_t root, 
    struct nk_net_ethernet_collective *col)
{
    if (root >= col->num_nodes) {
        return 0;
    }

    if (!__sync_bool_compare_and_swap(&col->current_mode, COLLECTIVE_IDLE, COLLECTIVE_GATHER)) {
    	DEBUG("Collective operation already in progress\n");
	    return -1;    
    } 

    if (!__sync_bool_compare_and_swap(&col->gather_state, GATHER_IDLE, GATHER_UP)) {
        DEBUG("Collective already in gather\n");
        return -1;
    }

    //init gen
    !col->gen ? col->gen = 1:col->gen++;
    col->maxlevel =  (col->my_node == 0) ? log2_ceil(col->num_nodes) : __builtin_ctz(col->my_node);
    col->curlevel = 0; 
    
    DEBUG("col->num_nodes: %d, col->maxlevel: %d, log2_ceil: %d\n", col->num_nodes, col->maxlevel, log2_ceil(col->num_nodes));
    col->root = root; 
    col->data_size = data_size;
    col->send_count = send_count;
    col->recv_count = recv_count;
    uint64_t buf_len = col->data_count_in_packet*col->data_size;
    char buf[buf_len];
    col->send_data = (void*)buf;
    memcpy(col->send_data,send_data,sizeof(send_data));
    nk_vc_printf("***1st val in send data: %d\n", *(int*)col->send_data);
    col->recv_data = recv_data;

    // recv_buffer here is for checking the arrival packet when tree up,
    // not related with the recv data, when all level packets arrive, state become to Down
    col->recv_buffer = malloc(col->maxlevel * sizeof(uint8_t)); 
    memset(col->recv_buffer, 0, col->maxlevel * sizeof(uint8_t));

    // check sender nodes exists or not
    int i;
    for (i = col->maxlevel - 1; (i >= 0) && ((pow2(i) + col->my_node) >= col->num_nodes); i--) {
        col->recv_buffer[i] = 1;
    }

    col->data_count_in_packet = pow2(i+1)*col->send_count;

    if (i < 0) {
        // if no send packet to this node
        // change mode to top to down packet
        gather_send_packet(col,0,col->gen);
        col->gather_state = GATHER_DOWN;
    }

    if (nk_net_ethernet_agent_device_receive_packet(col->netdev,
                        0,
                        NK_DEV_REQ_CALLBACK,
                        collective_recv_callback,
                        col)) {
        ERROR("Cannot initiate recevie\n");
        return -1;
    }

gather_initiate:
    {
        if (col->timeout_flag)
        {
        switch (__sync_fetch_and_or(&col->gather_state, 0)) {
            case GATHER_UP:
                col->curlevel = 0;
                memset(col->recv_buffer, 0, col->maxlevel * sizeof(uint8_t));
                // check sender nodes exists or not
                int i;
                for (i = col->maxlevel - 1; (i >= 0) && ((pow2(i) + col->my_node) >= col->num_nodes); i--) {
                    col->recv_buffer[i] = 1;
                }
                break;
            case GATHER_DOWN:
                gather_send_packet(col,0,col->gen);
                break;
            default:
                break;
            }
        }
    }

        uint64_t start = nk_sched_get_realtime();

    // wait for completion
    while (__sync_fetch_and_or(&col->current_mode,0)==COLLECTIVE_GATHER) {
	// do not regenerate...
        if ((nk_sched_get_realtime()-start) > REGEN_DELAY_NS) {
            // relaunch the packet if we have been waiting too long
            col->timeout_flag = 1;
            DEBUG("gather time out, resend!\n");
            goto gather_initiate;
            }
     }
    col->timeout_flag = 0;
    return 0;
}

int scatter_send_packet(struct nk_net_ethernet_collective *col, uint8_t dir, uint32_t gen) 
{

    DEBUG("scatter_send_packet, col->maxlevel=%d\n", col->maxlevel); 
    int i;
    nk_ethernet_packet_t *p = nk_net_ethernet_alloc_packet(-1);
    // recv_count is the number of data sent to each node, in packet we should include all data (recv_count*num_nodes),
    // when receive data, each node gets its corresponding part.
    uint64_t data_len = col->recv_count*col->num_nodes*col->data_size;
    uint64_t buf_len = sizeof(scatter_data_t)+data_len;
    char buf[buf_len];
    scatter_data_t *b = (scatter_data_t*)buf;

    b->dir = dir;
    b->level = col->maxlevel;
    b->gen = gen;
    memcpy(b->data, col->send_data, data_len);

    DEBUG("Send packet of genration of %d\n", gen);
    if (!p) {
	        ERROR("Cannot allocate packet\n");
	        return -1;
	    }
	    
    switch(dir){
        case 0:
            // Send to node 0
            encode_packet(p,
                col->macs[0], 
                col->macs[col->my_node],
                col->type,
                COLLECTIVE_SCATTER_TYPE,
                b,
                buf_len);

            if (nk_net_ethernet_agent_device_send_packet(col->netdev,
                                        p,
                                        NK_DEV_REQ_NONBLOCKING,
                                        0, 0)) {
                    DEBUG("Initiator cannot launch packet\n");
                    return -1;
                }
                break;
        case 1:
            for (i = col->maxlevel-1; i >= 0; i--)
            {   
                b->level = i;
                int dst_index = col->my_node + pow2(i);
                DEBUG("my_node: %d, num_nodes: %d, dst: %d\n", col->my_node, col->num_nodes, dst_index);
                if (dst_index < col->num_nodes) {
                    encode_packet(p,
                            col->macs[col->my_node + pow2(i)],
                            col->macs[col->my_node],
                            col->type,
                            COLLECTIVE_SCATTER_TYPE,
                            b,
                            buf_len);
                    if (nk_net_ethernet_agent_device_send_packet(col->netdev,
                                    p,
                                    NK_DEV_REQ_NONBLOCKING,
                                    0, 0)) {
                        DEBUG("Initiator cannot launch packet\n");
                        return -1;
                    }
                }
            }
            break;
        case 2:
            // Send to root node
            DEBUG("Send packet, dest: %d src: %d\n", col->root, col->my_node);
            encode_packet(p,
                col->macs[col->root], 
                col->macs[col->my_node],
                col->type,
                COLLECTIVE_SCATTER_TYPE,
                b,
                buf_len);

            if (nk_net_ethernet_agent_device_send_packet(col->netdev,
                                        p,
                                        NK_DEV_REQ_NONBLOCKING,
                                        0, 0)) {
                    DEBUG("Initiator cannot launch packet\n");
                    return -1;
                }
                break;
        default:
            break;
    } 
    return 0;
}

static int scatter_recv_callback(nk_net_dev_status_t status,
				  nk_ethernet_packet_t *packet,
				  void *state)
{

    struct nk_net_ethernet_collective *col = (struct nk_net_ethernet_collective *)state;

    ethernet_mac_addr_t *dest, *src;
    uint16_t subtype;
    uint32_t level;
    uint8_t dir;
    scatter_data_t *scatter = malloc(sizeof(scatter_data_t));
    uint16_t scatter_len;

    DEBUG("State :%d\n", col->scatter_state);

    if (status!=NK_NET_DEV_STATUS_SUCCESS) {
        ERROR("Receive failure - the token will have to be regenerated\n");
        return -1;
    }

    if (decode_packet_in_place(packet,
                    &dest,
                    &src,
                    col->type,
                    COLLECTIVE_SCATTER_TYPE,
                    (void **)(&scatter),
                    &scatter_len)) {
        DEBUG("Packet does not match current operation\n");
        return -1; 
    }

    if (memcmp(dest, col->macs[col->my_node], 6) !=0) {
        DEBUG("Discarding scatter packet for wrong destination, dest: %02d, my macs: %02d\n", (*dest)[5], col->macs[col->my_node][5]);
        nk_net_ethernet_release_packet(packet);
        return -1;
    }

    if(scatter->gen > col->gen){
        DEBUG("We are behand, drop packet.\n");
        nk_net_ethernet_release_packet(packet);
        return -1; 
    }

    if(scatter->gen < col->gen || col->scatter_state == SCATTER_IDLE){
        DEBUG("Got scatter packet for wrong generation, just go through it, scatter->gen: %02d, col->gen: %02d\n", scatter->gen, col->gen);
        DEBUG("-------scatter->dir = %d--------\n", scatter->dir);
        if(scatter->dir == 0){
            if(col->my_node == 0){ // if we are at top of tree, just change it into down dierction.
                scatter_send_packet(col, 1, scatter->gen);
            }
            else{
                // send to 0 node
                scatter_send_packet(col, 0, scatter->gen);
            }
        }
        else if (scatter->dir == 2){
            DEBUG("Got retransmission request!\n");
            // retransmission request to root
            if (col->root != col->my_node){
                DEBUG("Got wrong packet, it should send to root, I am not root\n");
                return -1;
            }
            // if I am root, resend packet to 0 node again
            scatter_send_packet(col, 0, scatter->gen);
        }
        else{
            // just send packet down
            scatter_send_packet(col, 1, scatter->gen);
        }
        return 1;
    }

    uint64_t recv_len = col->recv_count*col->data_size; // caclulate each node received data length.
    memcpy(col->send_data, scatter->data, recv_len*col->num_nodes);
    // calculate offset, to get the coresponding part
    memcpy(col->recv_data, scatter->data+col->my_node*recv_len, recv_len);

    if (col->scatter_state == SCATTER_UP){
        if (scatter->dir!=0) {
	        DEBUG("Discarding scatter packet for wrong direction...\n");
	        nk_net_ethernet_release_packet(packet);
	        return -1;
        }
        if (scatter_send_packet(col, 1, col->gen)){
            ERROR("Send packet down error.\n");
            return -1;
            }

        __sync_lock_test_and_set(&col->scatter_state, SCATTER_IDLE);
        __sync_lock_test_and_set(&col->current_mode, COLLECTIVE_IDLE);
        return 0;

    }
    
    if (col->scatter_state == SCATTER_DOWN){
        if (scatter->dir!=1) {
	        DEBUG("Discarding scatter packet for wrong direction...\n");
	        nk_net_ethernet_release_packet(packet);
	        return -1;
        }

        if (col->curlevel == scatter->level || col->my_node == 0) {
            if (scatter_send_packet(col, 1, col->gen)){
                ERROR("Send packet down error.\n");
                return -1;
            }

        __sync_lock_test_and_set(&col->scatter_state, SCATTER_IDLE);
        __sync_lock_test_and_set(&col->current_mode, COLLECTIVE_IDLE);
        return 0;
        }  
    } 
}

nk_net_ethernet_collective_scatter(void *send_data,
    uint64_t send_count, 
    uint32_t data_size,
    void *recv_data, 
    uint64_t recv_count,
    uint32_t root, 
    struct nk_net_ethernet_collective *col)
{
    if (root >= col->num_nodes) {
        return 0;
    } 

    if (!__sync_bool_compare_and_swap(&col->current_mode, COLLECTIVE_IDLE, COLLECTIVE_SCATTER)) {
    	DEBUG("Collective operation already in progress\n");
	    return -1;    
    }

    if (col->my_node == 0) {
        if (!__sync_bool_compare_and_swap(&col->scatter_state, SCATTER_IDLE, SCATTER_UP)) {
            DEBUG("Collective already in scatter\n");
            return -1;
        }
    }
    else {
        if (!__sync_bool_compare_and_swap(&col->scatter_state, SCATTER_IDLE, SCATTER_DOWN)) {
            DEBUG("Collective already in scatter\n");
            return -1;        
        }
    }

    //init gen
    !col->gen ? col->gen = 1:col->gen++;
    col->maxlevel =  (col->my_node == 0) ? log2_ceil(col->num_nodes) : __builtin_ctz(col->my_node);
    col->curlevel = col->maxlevel; 
    
    DEBUG("col->num_nodes: %d, col->maxlevel: %d, log2_ceil: %d\n", col->num_nodes, col->maxlevel, log2_ceil(col->num_nodes));
    
    col->root = root; 
    col->send_count = send_count;
    col->recv_count = recv_count;
    col->send_data = send_data;
    col->recv_data = recv_data;
    col->data_size = data_size;

    if (col->my_node == root){
        nk_ethernet_packet_t *p = nk_net_ethernet_alloc_packet(-1);
        if(!p){
            ERROR("Cannot allocate packet\n");
            return -1;
        }
        if (root == 0){ // Cannot send packet to itself(0), directely scatter.
            if (scatter_send_packet(col, 1, col->gen)){
                ERROR("Send packet down error.\n");
                return -1;
            }

            __sync_lock_test_and_set(&col->scatter_state, SCATTER_IDLE);
            __sync_lock_test_and_set(&col->current_mode, COLLECTIVE_IDLE);

        }
        else {
            // send to 0 node
            if (scatter_send_packet(col, 0, col->gen)){
                ERROR("Send packet down error.\n");
                return -1;
            }
        }
    }
    // if this node is not root, directly goto receive packet
    if (nk_net_ethernet_agent_device_receive_packet(col->netdev,
                    0,
                    NK_DEV_REQ_CALLBACK,
                    collective_recv_callback,
                    col)) {
    ERROR("Cannot initiate recevie\n");
    return -1;
        }

    scatter_initiate:
        if (col->timeout_flag){
            switch (__sync_fetch_and_or(&col->scatter_state, 0)) {
                case SCATTER_UP:
                    break;
                case SCATTER_DOWN:
                    if (col->my_node == root){ // if I am root, just send to 0 node again
                        scatter_send_packet(col, 0, col->gen);
                    }
                    else{ // send to root
                        scatter_send_packet(col, 2, col->gen);
                    }
                    break;
                default:
                    break;
            }
        }

    uint64_t start = nk_sched_get_realtime();

    // wait for completion
    while (__sync_fetch_and_or(&col->current_mode,0)==COLLECTIVE_SCATTER) {
        //bcast do not regenerate...
        if ((nk_sched_get_realtime()-start) > REGEN_DELAY_NS) {
            // relaunch the packet if we have been waiting too long
            col->timeout_flag = 1;
            DEBUG("scatter time out, resend!\n");
            goto scatter_initiate;
            }
    }
    col->timeout_flag = 0;
    return 0;

}

int bcast_send_packet(struct nk_net_ethernet_collective *col, uint8_t dir, uint32_t gen) 
{
    DEBUG("bcast_send_packet, col->maxlevel=%d\n", col->maxlevel); 
    int i;
    nk_ethernet_packet_t *p = nk_net_ethernet_alloc_packet(-1);
    uint64_t buf_len = sizeof(bcast_data_t)+col->data_len;
    char buf[buf_len];
    bcast_data_t *b = (bcast_data_t*)buf;

    b->dir = dir;
    b->level = col->maxlevel;
    b->gen = gen;
    memcpy(b->data, col->data, col->data_len);

    DEBUG("Send packet of generation of %d\n", gen);
    if (!p) {
	        ERROR("Cannot allocate packet\n");
	        return -1;
	    }
	    
    switch(dir){
        case 0:
            DEBUG("my_node: %d, num_nodes: %d, dst: 0\n", col->my_node, col->num_nodes);
            // Send to node 0
            encode_packet(p,
                col->macs[0], 
                col->macs[col->my_node],
                col->type,
                COLLECTIVE_BCAST_TYPE,
                b,
                buf_len);

            if (nk_net_ethernet_agent_device_send_packet(col->netdev,
                                        p,
                                        NK_DEV_REQ_NONBLOCKING,
                                        0, 0)) {
                    DEBUG("Initiator cannot launch packet\n");
                    return -1;
                }
                break;
        case 1:
            for (i = col->maxlevel-1; i >= 0; i--)
            {   
                b->level = i;
                int dst_index = col->my_node + pow2(i);
                DEBUG("my_node: %d, num_nodes: %d, dst: %d\n", col->my_node, col->num_nodes, dst_index);
                if (dst_index < col->num_nodes) {
                    encode_packet(p,
                            col->macs[col->my_node + pow2(i)],
                            col->macs[col->my_node],
                            col->type,
                            COLLECTIVE_BCAST_TYPE,
                            b,
                            buf_len);
                    if (nk_net_ethernet_agent_device_send_packet(col->netdev,
                                    p,
                                    NK_DEV_REQ_NONBLOCKING,
                                    0, 0)) {
                        DEBUG("Initiator cannot launch packet\n");
                        return -1;
                    }
                }
            }
            break;
        case 2:
            // Send to root node
            DEBUG("Send packet, dest: %d src: %d\n", col->root, col->my_node);
            encode_packet(p,
                col->macs[col->root], 
                col->macs[col->my_node],
                col->type,
                COLLECTIVE_BCAST_TYPE,
                b,
                buf_len);

            if (nk_net_ethernet_agent_device_send_packet(col->netdev,
                                        p,
                                        NK_DEV_REQ_NONBLOCKING,
                                        0, 0)) {
                    DEBUG("Initiator cannot launch packet\n");
                    return -1;
                }
                break;
        default:
            break;
    } 
    return 0;
}

static int bcast_recv_callback(nk_net_dev_status_t status,
				  nk_ethernet_packet_t *packet,
				  void *state)
{
    struct nk_net_ethernet_collective *col = (struct nk_net_ethernet_collective *)state;

    ethernet_mac_addr_t *dest, *src;
    uint16_t subtype;
    char buf[5];
    uint32_t level;
    uint8_t dir;
    bcast_data_t *bcast = malloc(sizeof(bcast_data_t));
    uint16_t bcast_len;

    DEBUG("State :%d\n", col->bcast_state);

    if (status!=NK_NET_DEV_STATUS_SUCCESS) {
        ERROR("Receive failure - the token will have to be regenerated\n");
        return -1;
    }
    if (decode_packet_in_place(packet,
                    &dest,
                    &src,
                    col->type,
                    COLLECTIVE_BCAST_TYPE,
                    (void **)(&bcast),
                    &bcast_len)) {
        DEBUG("Packet does not match current operation\n");
        return -1; 
    }

    if (memcmp(dest, col->macs[col->my_node], 6) !=0) {
        DEBUG("Discarding bcast packet for wrong destination, dest: %02d, my macs: %02d\n", (*dest)[5], col->macs[col->my_node][5]);
        nk_net_ethernet_release_packet(packet);
        return -1;
    }

    if(bcast->gen > col->gen){
        DEBUG("We are behand, drop packet.\n");
        nk_net_ethernet_release_packet(packet);
        return -1; 
    }

    if(bcast->gen < col->gen || col->bcast_state == BCAST_IDLE){
        DEBUG("Got bcast packet for wrong generation, just go through it, bcast->gen: %02d, col->gen: %02d, src mac: %2d.\n", bcast->gen, col->gen, (*src)[5]);
        DEBUG("-------bcast->dir = %d--------\n", bcast->dir);
        if(bcast->dir == 0){
            if(col->my_node == 0){ // if we are at top of tree, just change it into down dierction.
                bcast_send_packet(col, 1, bcast->gen);
            }
            else{
                // send to 0 node
                bcast_send_packet(col, 0, bcast->gen);
            }
        }
        else if (bcast->dir == 2){
            DEBUG("Got retransmission request!\n");
            // Got retransmission request to root
            if (col->root != col->my_node){
                DEBUG("Got wrong packet, it should send to root, I am not root\n");
                return -1;
            }
            // if I am root, resend packet to 0 node again
            bcast_send_packet(col, 0, bcast->gen);
        }
        else{
            // just send packet down
            bcast_send_packet(col, 1, bcast->gen);
        }
        return 1;
    }

    if (col->bcast_state == BCAST_UP){
        if (bcast->dir!=0) {
	        DEBUG("Discarding bcast packet for wrong direction...\n");
	        nk_net_ethernet_release_packet(packet);
	        return -1;
        }

        memcpy(col->data, bcast->data, col->data_len);

        if (bcast_send_packet(col, 1, col->gen)){
            ERROR("Send packet down error.\n");
            return -1;
            }

        __sync_lock_test_and_set(&col->bcast_state, BCAST_IDLE);
        __sync_lock_test_and_set(&col->current_mode, COLLECTIVE_IDLE);
        return 0;
    }
    
    if (col->bcast_state == BCAST_DOWN){
        if (bcast->dir!=1) {
	        DEBUG("Discarding bcast packet for wrong direction...\n");
	        nk_net_ethernet_release_packet(packet);
	        return -1;
        }

        memcpy(col->data, bcast->data, col->data_len);

        if (col->curlevel == bcast->level || col->my_node == 0) {
            if (bcast_send_packet(col, 1, col->gen)){
                ERROR("Send packet down error.\n");
                return -1;
            }

        __sync_lock_test_and_set(&col->bcast_state, BCAST_IDLE);
        __sync_lock_test_and_set(&col->current_mode, COLLECTIVE_IDLE);
        return 0;
        }  
    } 

}

int nk_net_ethernet_collective_bcast(struct nk_net_ethernet_collective *col, uint32_t root, void *data, uint64_t data_len)
{
    if (root >= col->num_nodes) {
        return 0;
    } 

    if (!__sync_bool_compare_and_swap(&col->current_mode, COLLECTIVE_IDLE, COLLECTIVE_BCAST)) {
    	DEBUG("Collective operation already in progress\n");
	    return -1;    
    }

    if (col->my_node == 0) {
        if (!__sync_bool_compare_and_swap(&col->bcast_state, BCAST_IDLE, BCAST_UP)) {
            DEBUG("Collective already in bcast\n");
            return -1;
        }
    }
    else {
        if (!__sync_bool_compare_and_swap(&col->bcast_state, BCAST_IDLE, BCAST_DOWN)) {
            DEBUG("Collective already in bcast\n");
            return -1;        
        }
    }
    // init generation
    !col->gen ? col->gen = 1:col->gen++;
    col->maxlevel =  (col->my_node == 0) ? log2_ceil(col->num_nodes) : __builtin_ctz(col->my_node);
    col->curlevel = col->maxlevel; 
    
    DEBUG("col->num_nodes: %d, col->maxlevel: %d, log2_ceil: %d\n", col->num_nodes, col->maxlevel, log2_ceil(col->num_nodes));
    
    col->root = root; 
    col->data_len = data_len;
    col->data = data;
    if (col->my_node == root){
        if (root == 0){ // Cannot send packet to itself(0), directely broadcast.
            if (bcast_send_packet(col, 1, col->gen)){
                ERROR("Send packet down error.\n");
                return -1;
            }

            __sync_lock_test_and_set(&col->bcast_state, BCAST_IDLE);
            __sync_lock_test_and_set(&col->current_mode, COLLECTIVE_IDLE);

        }
        else {
            // send to 0 node
            if (bcast_send_packet(col, 0, col->gen)){
                ERROR("Send packet up error.\n");
                return -1;
            }
        }
    }
    // if this node is not root, directly goto receive packet
    if (nk_net_ethernet_agent_device_receive_packet(col->netdev,
                    0,
                    NK_DEV_REQ_CALLBACK,
                    collective_recv_callback,
                    col)) {
    ERROR("Cannot initiate recevie\n");
    return -1;
        }

    bcast_initiate:
        if (col->timeout_flag){
            switch (__sync_fetch_and_or(&col->bcast_state, 0)) {
                case BCAST_UP:
                    break;
                case BCAST_DOWN:
                    if (col->my_node == root && col->my_node != 0){ // if I am root, just send to 0 node again
                        bcast_send_packet(col, 0, col->gen);
                    }
                    else if(col->my_node == root && col->my_node == 0){ // if I am root and I am also 0 node, just send down
                        bcast_send_packet(col, 1, col->gen);
                    }
                    else{// send to root
                        bcast_send_packet(col, 2, col->gen); 
                    }
                    break;
                default:
                    break;
            }
        }

    uint64_t start = nk_sched_get_realtime();

    // wait for completion
    while (__sync_fetch_and_or(&col->current_mode,0)==COLLECTIVE_BCAST) {
        //bcast do not regenerate...
        if ((nk_sched_get_realtime()-start) > REGEN_DELAY_NS) {
            // relaunch the packet if we have been waiting too long
            col->timeout_flag = 1;
            DEBUG("bcast time out, resend!\n");
            goto bcast_initiate;
            }
    }
    col->timeout_flag = 0;
    return 0;
}

// Bcast end

int barrier_send_packet(struct nk_net_ethernet_collective *col, uint8_t dir, uint32_t gen)
{
    DEBUG("Send packet of generation of %d\n", gen);
    DEBUG("barrier_send_packet, col->maxlevel=%d\n", col->maxlevel); 
    int i;
    barrier_data_t b = {.dir=dir, .level=col->maxlevel, .gen = gen};
    nk_ethernet_packet_t *p = nk_net_ethernet_alloc_packet(-1);
    if (!p) {
        ERROR("Cannot allocate packet\n");
        return -1;
    }
    switch (dir){
        case 0:
            if (col->my_node < pow2(col->maxlevel)) {
                return 0;
            }
            encode_packet(p,
                    col->macs[col->my_node - pow2(col->maxlevel)],
                    col->macs[col->my_node],
                    col->type,
                    COLLECTIVE_BARRIER_TYPE,
                    &b,
                    sizeof(b));
            if (nk_net_ethernet_agent_device_send_packet(col->netdev,
                         p,
                         NK_DEV_REQ_NONBLOCKING,
                         0,
                         0)) {
                    DEBUG("Initiator cannot launch packet\n");
                    return -1;
            }
            break;
        case 1:
            for (i = col->maxlevel-1; i >= 0; i--)
            {
                b.level = i;
                barrier_data_t b = {.dir=dir, .level=i, .gen = gen};
        
                int dst_index = col->my_node + pow2(i);
                DEBUG("my_node: %d, num_nodes: %d, dst: %d\n", col->my_node, col->num_nodes, dst_index);
                if (dst_index < col->num_nodes) {
                    encode_packet(p,
                            col->macs[col->my_node + pow2(i)],
                            col->macs[col->my_node],
                            col->type,
                            COLLECTIVE_BARRIER_TYPE,
                            &b,
                            sizeof(b));
                    
                    if (nk_net_ethernet_agent_device_send_packet(col->netdev,
                                    p,
                                    NK_DEV_REQ_NONBLOCKING,
                                    0, 0)) {
                        DEBUG("Initiator cannot launch packet\n");
                        return -1;
                    }
                }

            }
            break;
        default:
            break;
    }
    return 0;
}

static int barrier_recv_callback(nk_net_dev_status_t status,
				  nk_ethernet_packet_t *packet,
				  void *state)
{
    struct nk_net_ethernet_collective *col = (struct nk_net_ethernet_collective *)state;

    ethernet_mac_addr_t *dest, *src;
    uint16_t subtype;
    uint32_t level;
    uint8_t dir;
    barrier_data_t *bar = malloc(sizeof(barrier_data_t));
    uint16_t barlen;

    DEBUG("State :%d\n", col->barrier_state);

    if (status!=NK_NET_DEV_STATUS_SUCCESS) {
        ERROR("Receive failure - the token will have to be regenerated\n");
        return -1;
    }

    if (decode_packet_in_place(packet,
			       &dest,
			       &src,
			       col->type,
			       COLLECTIVE_BARRIER_TYPE,
			       (void **)(&bar),
			       &barlen)) {
	    DEBUG("Packet does not match current operation\n");
        return -1; 
    }
    
    if(bar->gen > col->gen){
        DEBUG("We are behand, drop packet.\n");
        nk_net_ethernet_release_packet(packet);
        return -1; 
    }

    if(bar->gen < col->gen || col->barrier_state == BARRIER_IDLE){
        DEBUG("Got barrier packet for wrong generation, just go through it, bar->gen: %02d, col->gen: %02d\n", bar->gen, col->gen);
        if(bar->dir == 0){
            if(col->my_node == 0){ // if we are at top of tree, just change it into down dierction.
                barrier_send_packet(col, 1, bar->gen);
            }
            else{
                barrier_send_packet(col, 0, bar->gen);
            }
        }
        else{
            barrier_send_packet(col, bar->dir, bar->gen);
        }
        return 1;
    }

    if (memcmp(dest, col->macs[col->my_node], 6) !=0) {
        DEBUG("Discarding barrier packet for wrong destination, dest: %02d, my macs: %02d\n", (*dest)[5], col->macs[col->my_node][5]);
        nk_net_ethernet_release_packet(packet);
        return -1;
    }

    if (col->barrier_state == BARRIER_UP) {
	    if (bar->dir!=0) {
	        DEBUG("Discarding barrier packet for wrong direction...\n");
	        nk_net_ethernet_release_packet(packet);
	        return -1;
        }

    	DEBUG("bar_level: %d, curlevel: %d, maxlevel: %d\n", bar->level, col->curlevel, col->maxlevel);
	    
        if (bar->level < col->curlevel) {
	        DEBUG("Discarding barrier packet smaller than curlevel...\n");
	        nk_net_ethernet_release_packet(packet);
	        return -1;
        }

        col->recv_buffer[bar->level] = 1;
        
        while(col->curlevel < col->maxlevel && col->recv_buffer[col->curlevel] == 1) {
            col->curlevel++;
        }

        if (col->my_node == 0 && col->curlevel == col->maxlevel) {
	        // We are at the top of the tree and need to send the first packet down
	        // we will reuse
            memset(col->recv_buffer, 0, col->maxlevel * sizeof(uint8_t));
            if (barrier_send_packet(col,1,col->gen)) {
                ERROR("Send packet down error.\n");
                return -1;
            }
            
            __sync_lock_test_and_set(&col->barrier_state, BARRIER_IDLE); 
            __sync_lock_test_and_set(&col->current_mode, COLLECTIVE_IDLE);
            return 0;
        }
        
        if (col->my_node !=0 && col->maxlevel == col->curlevel){ 
            memcpy(packet->header.dst, col->macs[col->my_node - pow2(col->curlevel)], 6);
            memcpy(packet->header.src, col->macs[col->my_node], 6);
            
            bar->level = col->curlevel;
            bar->dir = 0;
            memcpy(packet->data+4, bar, sizeof(barrier_data_t));
            DEBUG("bar->level: %d\n", bar->level);
            
            memset(col->recv_buffer, 0, col->maxlevel * sizeof(uint8_t));

            if (nk_net_ethernet_agent_device_send_packet(col->netdev,
                                                         packet,
                                                         NK_DEV_REQ_NONBLOCKING,
                                                         0,
                                                         0)) {
                ERROR("Cannot launch packet barrier\n");
                return -1;
            }
            __sync_lock_test_and_set(&col->barrier_state, BARRIER_DOWN); 
            
        }
        return 1;
    }

    if (col->barrier_state == BARRIER_DOWN) {
	    if (bar->dir != 1) {
	        DEBUG("Discarding barrier packet for wrong direction...\n");
	        nk_net_ethernet_release_packet(packet);
	        return -1;
        }

        DEBUG("col->curlevel = %d\n",col->curlevel);
        if (col->curlevel < bar->level || col->curlevel == bar->level) {
            if (barrier_send_packet(col,1,col->gen)) {
                ERROR("Send pacekt down error.\n");
                return -1;
            }
            
            __sync_lock_test_and_set(&col->barrier_state, BARRIER_IDLE); 
            __sync_lock_test_and_set(&col->current_mode, COLLECTIVE_IDLE);
            return 0;
        }
    }

}

// The actual barrier can be executed as many times as desired
int nk_net_ethernet_collective_barrier(struct nk_net_ethernet_collective *col)
{
    if (col->num_nodes == 1) {
	    return 0;
    }

    if (!__sync_bool_compare_and_swap(&col->current_mode,COLLECTIVE_IDLE,COLLECTIVE_BARRIER)) {
	    DEBUG("Collective operation already in progress\n");
	    return -1;
    }

    if (!__sync_bool_compare_and_swap(&col->barrier_state, BARRIER_IDLE, BARRIER_UP)) {
        DEBUG("Collective already in barrier\n");
        return -1;
    }
    //init generation
    !col->gen ? col->gen = 1:col->gen++;
    col->curlevel = 0;  // leaves
    col->maxlevel = (col->my_node == 0) ? log2_ceil(col->num_nodes) : __builtin_ctz(col->my_node);

    DEBUG("col->num_nodes: %d, col->maxlevel: %d, log2_ceil: %d\n", col->num_nodes, col->maxlevel, log2_ceil(col->num_nodes));
    
    col->recv_buffer = malloc(col->maxlevel * sizeof(uint8_t));
    memset(col->recv_buffer, 0, col->maxlevel * sizeof(uint8_t));
    
    // check sender nodes exists or not
    int i;
    for (i = col->maxlevel - 1; (i >= 0) && ((pow2(i) + col->my_node) >= col->num_nodes); i--) {
        col->recv_buffer[i] = 1;
    }

    if (i < 0) {
        // if no send packet to this node
        // change mode to top to down packet
        barrier_send_packet(col,0,col->gen);
        col->barrier_state = BARRIER_DOWN;
    }

    if (nk_net_ethernet_agent_device_receive_packet(col->netdev,
                        0,
                        NK_DEV_REQ_CALLBACK,
                        collective_recv_callback,
                        col)) {
        ERROR("Cannot initiate recevie\n");
        return -1;
    }
    barrier_initiate:
    {
        if (col->timeout_flag)
        {
        switch (__sync_fetch_and_or(&col->barrier_state, 0)) {
            case BARRIER_UP:
                col->curlevel = 0;
                memset(col->recv_buffer, 0, col->maxlevel * sizeof(uint8_t));
                // check sender nodes exists or not
                int i;
                for (i = col->maxlevel - 1; (i >= 0) && ((pow2(i) + col->my_node) >= col->num_nodes); i--) {
                    col->recv_buffer[i] = 1;
                }

                break;
            case BARRIER_DOWN:
                barrier_send_packet(col,0,col->gen);
                break;
            default:
                break;
            }
        }
    }
    
    uint64_t start = nk_sched_get_realtime();

    // wait for completion
    while (__sync_fetch_and_or(&col->current_mode,0)==COLLECTIVE_BARRIER) {
	//barriers do not regenerate...
        if ((nk_sched_get_realtime()-start) > REGEN_DELAY_NS) {
            // relaunch the packet if we have been waiting too long
            col->timeout_flag = 1;
            DEBUG("barrier time out, resend!\n");
            goto barrier_initiate;
            }
     }
    col->timeout_flag = 0;
    return 0;
}

#if 0
	    
int nk_net_ethernet_collective_barrier(struct nk_net_ethernet_collective *col)
{
    return -1;
}

#endif
	    
// Data in a ring packet:   token
//

static void ring_recv_callback(nk_net_dev_status_t status,
			       nk_ethernet_packet_t *packet,
			       void *state)
{
    struct nk_net_ethernet_collective *col = (struct nk_net_ethernet_collective *)state;

    ethernet_mac_addr_t *dest, *src;
    uint16_t subtype;
    void *token;
    uint16_t token_len;

    /*uint64_t temp = nk_sched_get_realtime() / 1000;
    if ((temp % 10) < 2) {
        DEBUG("Release packet, temp: %ld\n", temp);
        goto RING_RECV;
    }*/

    if (__sync_fetch_and_or(&col->current_mode, 0) != COLLECTIVE_RING) {
        ERROR("COLLNET STATUS ERROR\n");
        goto RING_RECV;
    }

    if (status!=NK_NET_DEV_STATUS_SUCCESS) {
	    ERROR("Receive failure - the token will have to be regenerated\n");
	    goto RING_RECV;
    }

    if (decode_packet_in_place_test(packet,
			       &dest,
			       &src,
			       col->type,
			       &subtype,
			       &token,
			       &token_len)) {
	    DEBUG("Packet does not match current operation\n");
	    goto RING_RECV;
    }

    switch (__sync_fetch_and_or(&col->ring_state, 0)) {
        case RING_STATE_1:
            if (subtype == COLLECTIVE_RING_STATE_1) {
                __sync_lock_test_and_set(&col->ring_state, RING_STATE_2);
            } else {
                DEBUG("Shouldn't receive such packet, RING_STATE_1 subtype: %d\n", subtype);
                goto RING_RECV;
            }
            break;
        case RING_STATE_2:
            if (subtype == COLLECTIVE_RING_STATE_2) {
                __sync_lock_test_and_set(&col->ring_state, RING_IDLE);
                __sync_lock_test_and_set(&col->current_mode, COLLECTIVE_IDLE);
            } else if (subtype == COLLECTIVE_RING_STATE_1) {
                DEBUG("Lost packet during the ring, resend it.\n");
            } else {
                DEBUG("Shouldn't receive such packet, RING_STATE_2 subtype: %d\n", subtype);
                goto RING_RECV;
            }
            break;
        default:
            break;
    }

    DEBUG("Received token packet\n");

    if (token_len<col->token_len) {
	    token_len = col->token_len;
    }
   
    memcpy(col->token,token,token_len);
     
    if (!col->initiator) {
	// we will send the same packet to our neighbor;

	    memcpy(packet->header.dst, col->macs[(col->my_node + 1) % col->num_nodes], 6);

	    memcpy(packet->header.src, col->macs[col->my_node], 6);

	// all else is the same
	    if (nk_net_ethernet_agent_device_send_packet(col->netdev,
						     packet,
						     NK_DEV_REQ_NONBLOCKING,
						     0, 0)) {
	        ERROR("Cannot launch packet mid ring\n");
            goto RING_RECV;
	    }
    }
   
RING_RECV:
    if (nk_net_ethernet_agent_device_receive_packet(col->netdev,
						    0,
						    NK_DEV_REQ_CALLBACK,
						    ring_recv_callback,
						    col)) {
	    ERROR("Cannot initiate receive\n");
        return;
    }
}

// circulate a token among the nodes in the barrier
// for two nodes, this is a ping-pong
int nk_net_ethernet_collective_ring(struct nk_net_ethernet_collective *col, void *token, uint64_t token_len, int initiate)
{ 
    if (token_len>NET_ETHERNET_COLLECTIVE_MAX_TOKEN_LEN) {
	    DEBUG("token length unsupported\n");
	    return -1;
    }

    uint16_t collective_type = __sync_fetch_and_or(&col->current_mode, 0);
    if (collective_type != COLLECTIVE_IDLE) {
	    DEBUG("Collective operation already in progress\n");
	    return -1;
    }

    __sync_lock_test_and_set(&col->current_mode, COLLECTIVE_RING);

    if (col->num_nodes == 1) {
	    return 0;
    }
    
    if (!__sync_bool_compare_and_swap(&col->ring_state, RING_IDLE, RING_STATE_1)) {
        DEBUG("Ring operation already in progress\n");
        return -1;
    }

    col->initiator = initiate;
    col->token = token;
    col->token_len = token_len;
    
    // everyone posts receive for left
    if (nk_net_ethernet_agent_device_receive_packet(col->netdev,
						    0,
						    NK_DEV_REQ_CALLBACK,
						    ring_recv_callback,
						    col)) {
	    ERROR("Cannot initiate receive\n");
	    return -1;
    }

 do_initiate:
    // initiator also launches the first packet
    if (initiate) {
	    nk_ethernet_packet_t *p = nk_net_ethernet_alloc_packet(-1);
        
        int flag = 0;
	    if (!p) {
	        ERROR("Cannot allocate packet\n");
	        return -1;
	    }

        switch (__sync_fetch_and_or(&col->ring_state, 0)) {
            case RING_STATE_1:
	            encode_packet(p,
		                col->macs[(col->my_node + 1) % col->num_nodes],
		                col->macs[col->my_node],
		                col->type,
		                COLLECTIVE_RING_STATE_1,
		                token,
		                token_len);
                break;
            case RING_STATE_2:
                encode_packet(p,
		                col->macs[(col->my_node + 1) % col->num_nodes],
		                col->macs[col->my_node],
		                col->type,
		                COLLECTIVE_RING_STATE_2,
		                token,
		                token_len);
                break;
            default:
                flag = 1;
                break;
        }
       
        if (flag != 1) {
            if (nk_net_ethernet_agent_device_send_packet(col->netdev,
						     p,
						     NK_DEV_REQ_NONBLOCKING,
						     0, 0)) {
	            DEBUG("Initiator cannot launch packet\n");
	            return -1;
	        }
        }
    }

    uint64_t start = nk_sched_get_realtime();
    
    // wait for completion
    while (__sync_fetch_and_or(&col->ring_state, 0) != RING_IDLE) {
        if ((nk_sched_get_realtime()-start) > REGEN_DELAY_NS) {
	        // relaunch the packet if we have been waiting too long
            goto do_initiate;
	    }
    }

    return 0;
}

struct nk_net_ethernet_collective *nk_net_ethernet_collective_create(struct nk_net_ethernet_agent *agent,
								     uint16_t    type,
								     uint32_t    num_nodes,
								     ethernet_mac_addr_t  macs[])
{
    uint64_t size = sizeof(struct nk_net_ethernet_collective)+sizeof(ethernet_mac_addr_t)*num_nodes;
    uint32_t i;
    
    struct nk_net_ethernet_collective *col = (struct nk_net_ethernet_collective *)malloc(size);

    if (!col) {
	    ERROR("Failed to allocate collective structure for %u nodes\n",num_nodes);
	    return 0;
    }

    memset(col,0,sizeof(*col));
    
    col->num_nodes = num_nodes;
    col->type = type;

    if (!(col->netdev = nk_net_ethernet_agent_register_type(agent, type))) {
	    ERROR("Cannot register with agent for type %x\n",type);
	    free(col);
	    return 0;
    }

    if (nk_net_dev_get_characteristics(col->netdev, &col->netchar)) {
    	ERROR("Failed to get network characterstics\n");
    	free(col);
	    return 0;
    }

    col->my_node = -1;
    for (i=0;i<num_nodes;i++) {
	    memcpy(col->macs[i],macs[i],6);
	    if (!memcmp(col->macs[i],col->netchar.mac,ETHER_MAC_LEN)) {
	        col->my_node = i;
            nk_vc_printf("I am Node %d \n", col->my_node);
	    }
    }
    
    if (col->my_node == -1 ) {
	    ERROR("I can't find myself among given mac addresses\n");
	    nk_net_ethernet_agent_unregister(col->netdev);
	    free(col);
	    return 0;
    }

    return col;
}
	      


int nk_net_ethernet_collective_destroy(struct nk_net_ethernet_collective *col)
{
    if (col->current_mode != COLLECTIVE_IDLE) {
	    return -1;
    } else {
	    nk_net_ethernet_agent_unregister(col->netdev);
	    free(col->recv_buffer);
        free(col);
	    return 0;
    }
}


int nk_net_ethernet_collective_init()
{
    INFO("inited\n");
    return 0;
}

void nk_net_ethernet_collective_deinit()
{
    INFO("deinited\n");
}


