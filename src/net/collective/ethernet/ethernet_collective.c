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

typedef enum {COLLECTIVE_IDLE=0, COLLECTIVE_BARRIER, COLLECTIVE_RING} mode_t;
typedef enum {BARRIER_IDLE=0, BARRIER_UP, BARRIER_DOWN} barrier_state_t;
typedef enum {RING_IDLE=0, RING_STATE_1, RING_STATE_2} ring_state_t;

// collective message types
#define COLLECTIVE_RING_STATE_1     0x1
#define COLLECTIVE_RING_STATE_2     0x2
#define COLLECTIVE_BARRIER_TYPE     0x3


struct nk_net_ethernet_collective {
    mode_t   current_mode;            // what operation we are handling
    
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

typedef struct barrier_data {
    uint8_t  dir;  // 0=UP, 1=DOWN
    uint32_t level;
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


int barrier_send_packet_down(struct nk_net_ethernet_collective *col)
{
    DEBUG("barrier_send_packet, col->maxlevel=%d\n", col->maxlevel); 
    int i;
    for (i = col->maxlevel-1; i >= 0; i--)
    {
        nk_ethernet_packet_t *p = nk_net_ethernet_alloc_packet(-1);
	    if (!p) {
	        ERROR("Cannot allocate packet\n");
	        return -1;
	    }

	    barrier_data_t b = {.dir=1, .level=i};
	    
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
    return 0;
}

static void barrier_recv_callback(nk_net_dev_status_t status,
				  nk_ethernet_packet_t *packet,
				  void *state)
{
    struct nk_net_ethernet_collective *col = (struct nk_net_ethernet_collective *)state;

    ethernet_mac_addr_t *dest, *src;
    uint16_t subtype;
    char buf[5];
    uint32_t level;
    uint8_t dir;
    barrier_data_t *bar = malloc(sizeof(barrier_data_t));
    uint16_t barlen;

    if (col->barrier_state == BARRIER_IDLE) {
        ERROR("Barrier idle");
        return;
    }

    if (status != NK_NET_DEV_STATUS_SUCCESS) {
        ERROR("Receive failure - the token will have to be regenerated\n");
        goto recv_finish;
    }

    if (decode_packet_in_place(packet,
			       &dest,
			       &src,
			       col->type,
			       COLLECTIVE_BARRIER_TYPE,
			       (void **)(&bar),
			       &barlen)) {
	    DEBUG("Packet does not match current operation\n");
        goto recv_finish; 
    }

    if (memcmp(dest, col->macs[col->my_node], 6) !=0) {
        DEBUG("Discarding barrier packet for wrong destination, dest: %02d, my macs: %02d\n", (*dest)[5], col->macs[col->my_node][5]);
        nk_net_ethernet_release_packet(packet);
        goto recv_finish;
    }

    if (col->barrier_state == BARRIER_UP) {
	    if (bar->dir!=0) {
	        DEBUG("Discarding barrier packet for wrong direction...\n");
	        nk_net_ethernet_release_packet(packet);
	        goto recv_finish;
        }

    	DEBUG("bar_level: %d, curlevel: %d, maxlevel: %d\n", bar->level, col->curlevel, col->maxlevel);
	    
        if (bar->level < col->curlevel) {
	        DEBUG("Discarding barrier packet smaller than curlevel...\n");
	        nk_net_ethernet_release_packet(packet);
	        goto recv_finish;
        }

        col->recv_buffer[bar->level] = 1;
        
        while(col->curlevel < col->maxlevel && col->recv_buffer[col->curlevel] == 1) {
            col->curlevel++;
        }

        if (col->my_node == 0 && col->curlevel == col->maxlevel) {
	        // We are at the top of the tree and need to send the first packet down
	        // we will reuse
            memset(col->recv_buffer, 0, col->maxlevel * sizeof(uint8_t));
            if (barrier_send_packet_down(col)) {
                ERROR("Send packet down error.\n");
                return;
            }
            
            col->current_mode = COLLECTIVE_IDLE;
            col->barrier_state = BARRIER_IDLE;
            return;
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
                return;
            }
            col->barrier_state = BARRIER_DOWN;
        }
        goto recv_finish;
    }

    if (col->barrier_state == BARRIER_DOWN) {
	    if (bar->dir != 1) {
	        DEBUG("Discarding barrier packet for wrong direction...\n");
	        nk_net_ethernet_release_packet(packet);
	        goto recv_finish;
        }

        //check (curlevel == bar->level) or not
        if (col->curlevel == bar->level) {
            if (barrier_send_packet_down(col)) {
                ERROR("Send pacekt down error.\n");
                return;
            }
            
            col->current_mode = COLLECTIVE_IDLE;
            col->barrier_state = BARRIER_IDLE;
            return;
        }
        goto recv_finish;
    }

recv_finish:
    if (nk_net_ethernet_agent_device_receive_packet(col->netdev,
                        0,
                        NK_DEV_REQ_CALLBACK,
                        barrier_recv_callback,
                        col)) {
        ERROR("Cannot ainitiate recevie\n");
        return;
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
   
    col->curlevel = 0;  // leaves
    col->maxlevel = (col->my_node == 0) ? log2_ceil(col->num_nodes) : __builtin_ctz(col->my_node);

    DEBUG("col->num_nodes: %d, col->maxlevel: %d, log2_ceil: %d\n", col->num_nodes, col->maxlevel, log2_ceil(col->num_nodes));
    
    col->recv_buffer = malloc(col->maxlevel * sizeof(uint8_t));
    memset(col->recv_buffer, 0, col->maxlevel * sizeof(uint8_t));
    
    // check sender nodes exists or not
    int i;
    for (i = col->maxlevel - 1; (i >= 0) && ((pow2(i) + col->my_node) >= col->num_nodes); i--) {
        col->recv_buffer[(pow2(i) + col->my_node)] = 1;
    }

    if (i < 0) {
        // if no send packet to this node
        // change mode to top to down packet
        nk_ethernet_packet_t *p = nk_net_ethernet_alloc_packet(-1);
        col->curlevel = col->maxlevel;
	    if (!p) {
	        ERROR("Cannot allocate packet\n");
	        return -1;
	    }

	    barrier_data_t b = {.dir=0, .level=col->maxlevel};
	
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
						     0, 0)) {
	        DEBUG("Initiator cannot launch packet\n");
	        return -1;
	    }
        col->barrier_state = BARRIER_DOWN;
    }

    if (nk_net_ethernet_agent_device_receive_packet(col->netdev,
                        0,
                        NK_DEV_REQ_CALLBACK,
                        barrier_recv_callback,
                        col)) {
        ERROR("Cannot initiate recevie\n");
        return -1;
    }

    uint64_t start = nk_sched_get_realtime();

    // wait for completion
    while (__sync_fetch_and_or(&col->current_mode,0)==COLLECTIVE_BARRIER) {
	// barriers do not regenerate...
    }
    
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

#define REGEN_DELAY_NS 10000000
// circulate a token among the nodes in the barrier
// for two nodes, this is a ping-pong
int nk_net_ethernet_collective_ring(struct nk_net_ethernet_collective *col, void *token, uint64_t token_len, int initiate)
{ 
    if (token_len>NET_ETHERNET_COLLECTIVE_MAX_TOKEN_LEN) {
	    DEBUG("token length unsupported\n");
	    return -1;
    }

    uint16_t collective_type = __sync_fetch_and_or(&col->current_mode, 0);
    if (collective_type == COLLECTIVE_BARRIER) {
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


