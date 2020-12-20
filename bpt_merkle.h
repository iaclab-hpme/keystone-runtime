#pragma once

#if defined(USE_FREEMEM) && defined(USE_PAGING)

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define BPT_DEGREE 5


typedef union bpt_merkle_node bpt_merkle_node_t;

union bpt_merkle_node {
  struct {
    // uintptr_t ptr;
    bool is_leaf;
    int8_t valid_num;
    uint8_t hash[32];
    uintptr_t addr_pivot[BPT_DEGREE+1];
    union{
      bpt_merkle_node_t* children[BPT_DEGREE+1];
      uint8_t  data[BPT_DEGREE][32];
    };
  };
  struct {
    uint64_t raw_words[40];
  };
};

void
bpt_merk_insert(bpt_merkle_node_t* root, uintptr_t key, const uint8_t hash[32]);
bool
bpt_merk_verify(
    bpt_merkle_node_t* root, uintptr_t key, const uint8_t hash[32]);
void
bpt_merk_travel(bpt_merkle_node_t* root);

#endif
