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

#ifndef __ETHERNET_COLLECTIVE__
#define __ETHERNET_COLLECTIVE__

#include <nautilus/naut_types.h>
#include <nautilus/netdev.h>
#include <net/ethernet/ethernet_packet.h>
#include <net/ethernet/ethernet_agent.h>

// Fast L2 collective communication, currently just barriers and rings

struct nk_net_ethernet_collective;


#define NET_ETHERNET_COLLECTIVE_DEFAULT_TYPE 0x1234

// create a collective that will run on a particular network device
// each node does exactly the same create call
// the position of the netdev's mac on the list of macs
// determines its rank in the collective
// the type argument is the ethernet type used to tag packets in this collective
struct nk_net_ethernet_collective *nk_net_ethernet_collective_create(struct nk_net_ethernet_agent *agent,
								     uint16_t             type,
								     uint32_t             num_nodes,
								     ethernet_mac_addr_t  macs[]);

// top level callback
static void collective_recv_callback(nk_net_dev_status_t status, nk_ethernet_packet_t *packet, void *state);
static int gather_recv_callback(nk_net_dev_status_t status, nk_ethernet_packet_t *packet, void *state);
static int scatter_recv_callback(nk_net_dev_status_t status, nk_ethernet_packet_t *packet, void *state);
static int bcast_recv_callback(nk_net_dev_status_t status, nk_ethernet_packet_t *packet, void *state);
static int barrier_recv_callback(nk_net_dev_status_t status, nk_ethernet_packet_t *packet, void *state);
static void ring_recv_callback(nk_net_dev_status_t status, nk_ethernet_packet_t *packet, void *state);

// return the rank of node
int nk_net_ethernet_collective_rank(struct nk_net_ethernet_collective *col, uint32_t* rank);

// scatter the data sent by root
int nk_net_ethernet_collective_scatter(void *send_data,
	uint64_t send_count, 
    uint32_t data_size,
    void *recv_data, 
    uint64_t recv_count,
    uint32_t root, 
    struct nk_net_ethernet_collective *col);

// broadcast the data sent by root
int nk_net_ethernet_collective_bcast(struct nk_net_ethernet_collective *col, uint32_t root, void *data, uint64_t data_len);

// barrier the collective
int nk_net_ethernet_collective_barrier(struct nk_net_ethernet_collective *col);

// circulate token data among the nodes in the collective
// the token is produced by the node that calls this with initiate=1
// until it circulates back to the same node
// for two nodes, this is a ping-pong
int nk_net_ethernet_collective_ring(struct nk_net_ethernet_collective *col, void *token, uint64_t token_len, int initiate);

int nk_net_ethernet_collective_ring_banding(struct nk_net_ethernet_collective *col);

#define NET_ETHERNET_COLLECTIVE_MAX_TOKEN_LEN 512


int nk_net_ethernet_collective_destroy(struct nk_net_ethernet_collective *col);


int nk_net_ethernet_collective_init();
void nk_net_ethernet_collective_deinit();

#endif
