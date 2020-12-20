#if defined (USE_PAGE_HASH_BPT)

#include "bpt_merkle.h"

#include <assert.h>


#include "paging.h"
#include "compiler.h"
#ifdef USE_SHA3_ROCC
#include "sha3.h"
#include "encoding.h"
#include "rocc.h"
#else // use software sha256
#include "sha256.h"
#endif

#ifndef MERK_SILENT
#define MERK_LOG printf
#else
#define MERK_LOG(...)
#endif

const uintptr_t unavailable = 0;

_Static_assert(sizeof(bpt_merkle_node_t) == 320, "bpt_merkle_node_t is not 320 bytes!");

#define BPT_MERK_NODES_PER_PAGE (RISCV_PAGE_SIZE / sizeof(bpt_merkle_node_t))

typedef struct bpt_merkle_page_freelist {
  uint64_t free[BPT_MERK_NODES_PER_PAGE / 12];
  uint16_t free_count;
  bool in_freelist;
  struct bpt_merkle_page_freelist* next;
} bpt_merkle_page_freelist_t;

_Static_assert(
    sizeof(bpt_merkle_page_freelist_t) <= sizeof(bpt_merkle_node_t),
    "bpt_merkle_page_freelist does not fit in one bpt_merkle_node_t!");

static bpt_merkle_page_freelist_t*
bpt_merk_alloc_page(void) {
  void* page                        = (void*)paging_alloc_backing_page();
  bpt_merkle_page_freelist_t* free_list = (bpt_merkle_page_freelist_t*)page;
  memset(free_list, 0, sizeof(*free_list));

  for (size_t i = 0; i < BPT_MERK_NODES_PER_PAGE; i += 12) {
    size_t this_page_nodes = BPT_MERK_NODES_PER_PAGE - i;
    free_list->free[i / 12] =
        (this_page_nodes < 12) * (1ull << this_page_nodes) - 1;
  }
  free_list->free[0] &= ~(uint64_t)1;
  free_list->free_count = BPT_MERK_NODES_PER_PAGE - 1;

  return free_list;
}


static bpt_merkle_page_freelist_t* bpt_merk_free_list = NULL;

static bpt_merkle_node_t*
bpt_merk_reserve_node_in_page(bpt_merkle_page_freelist_t* free_list) {
  if (!free_list->free_count) return NULL;

  for (size_t i = 0; i < BPT_MERK_NODES_PER_PAGE / 12; i++) {
    if (free_list->free[i]) {
      size_t free_idx = __builtin_ctzll(free_list->free[i]);
      free_list->free[i] &= ~(1ull << free_idx);
      free_list->free_count--;

      bpt_merkle_node_t* page = (bpt_merkle_node_t*)free_list;
      assert(free_idx != 0);

      return page + free_idx;
    }
  }
  return NULL;
}


static bpt_merkle_node_t*
bpt_merk_alloc_node(void) {
  while (bpt_merk_free_list && bpt_merk_free_list->free_count == 0) {
    // Clear out the unfree lists
    bpt_merk_free_list->in_freelist = false;
    bpt_merk_free_list              = bpt_merk_free_list->next;
  }

  if (!bpt_merk_free_list) {
    bpt_merk_free_list              = bpt_merk_alloc_page();
    bpt_merk_free_list->in_freelist = true;
  }

  bpt_merkle_node_t* out = bpt_merk_reserve_node_in_page(bpt_merk_free_list);
  memset(out, 0, sizeof(*out));
  return out;
}


static void
bpt_merk_calculate_node_hash(bpt_merkle_node_t* node, uint8_t calculated_hash[32]){
  #if defined (USE_SHA3_ROCC)
  uint8_t data_to_be_hashed[32 * BPT_DEGREE] __aligned(8);
  int data_size = 0;

  if(node->is_leaf){
    memcpy(data_to_be_hashed, node->data, 32 * node->valid_num);
    data_size += 32 * node->valid_num;
  }
  else{
    for(int i = 0;i < BPT_DEGREE; ++i){
      if(node->children[i]){
        memcpy(data_to_be_hashed+data_size, node->children[i]->hash, 32);
        data_size += 32;
      }
    }
  }


  asm volatile("fence");

  ROCC_INSTRUCTION_SS(2, data_to_be_hashed, calculated_hash, 0);

  ROCC_INSTRUCTION_S(2, data_size, 1);

  asm volatile("fence" ::: "memory");

  #else // software sha256

  SHA256_CTX hasher;
  sha256_init(&hasher);

  if(node->is_leaf){
    for(int i = 0;i < node->valid_num;++i)
      sha256_update(&hasher, node->data[i], 32);
  }
  else{
    for(int i = 0;i < node->valid_num;++i)
      sha256_update(&hasher, node->children[i]->hash, 32);
  }
  sha256_final(&hasher, calculated_hash);
  #endif
}


static bool
bpt_merk_verify_single_node(bpt_merkle_node_t* node){
  uint8_t calculated_hash[32] __aligned(8);
  bpt_merk_calculate_node_hash(node, calculated_hash);
  int result = memcmp(node->hash, calculated_hash, 32);
  if(result != 0){
    printf("error, branch node hash compare failed at %d\n", result);
  }
  return result == 0;
}


static void
bpt_merk_hash_single_node(
    bpt_merkle_node_t* node) {

  uint8_t calculated_hash[32] __aligned(8);
  bpt_merk_calculate_node_hash(node, calculated_hash);
  memcpy(node->hash, calculated_hash, 32);
}

// When inserting key, i is the position of node in parent, j is the position for the key to insert
// When inserting node, i is the position to be insterted, key, hash and j is useless
static bpt_merkle_node_t*
insert_element(bool is_key, bpt_merkle_node_t* parent, bpt_merkle_node_t* node, uintptr_t key, const uint8_t hash[32], int i, int j){
  int k;
  if(is_key){
    for(k = node->valid_num - 1;k >= j;--k){
      node->addr_pivot[k+1] = node->addr_pivot[k];
      memcpy(node->data[k+1], node->data[k], 32);
    }
    node->addr_pivot[j] = key;
    memcpy(node->data[j], hash, 32);
    if(parent){
      parent->addr_pivot[i] = node->addr_pivot[0];
    }
    node->valid_num += 1;
  }
  else{
    for(k = parent->valid_num-1;k >= i;--k){
      parent->children[k+1] = parent->children[k];
      parent->addr_pivot[k+1] = parent->addr_pivot[k];
    }
    parent->addr_pivot[i] = node->addr_pivot[0];
    parent->children[i] = node;
    parent->valid_num += 1;
  }
  return node;
}

static bpt_merkle_node_t*
split_node(bpt_merkle_node_t* parent, bpt_merkle_node_t* node, int i){
  int j, k, limit;
  bpt_merkle_node_t* new_node;
  new_node = bpt_merk_alloc_node();
  new_node->is_leaf = node->is_leaf;
  k = 0;
  j = node->valid_num / 2;
  limit = node->valid_num;
  while(j < limit){
    if(!node->is_leaf){
      new_node->children[k] = node->children[j];
      new_node->children[j] = NULL;
    }
    else{
      memcpy(new_node->data[k], node->data[j], 32);
    }
    new_node->addr_pivot[k] = node->addr_pivot[j];
    node->addr_pivot[j] = unavailable;
    new_node->valid_num += 1;
    node->valid_num -= 1;
    ++j;
    ++k;
  }

  if(parent){
    insert_element(0, parent, new_node, unavailable, NULL, i + 1, unavailable);
  }
  // node is the root, despite that we need to split the root and make a new root
  // the root's addr must not be changed, so we have to copy node to new node and
  // still make node to be root
  else{
    parent = bpt_merk_alloc_node();
    memcpy(parent, node, sizeof(bpt_merkle_node_t));
    memset(node, 0, sizeof(bpt_merkle_node_t));
    insert_element(0, node, parent, unavailable, NULL, 0, unavailable);
    insert_element(0, node, new_node, unavailable, NULL, 1, unavailable);
    // we do hash here when spliting the root, which seems akward
    bpt_merk_hash_single_node(new_node);
    bpt_merk_hash_single_node(parent);
    bpt_merk_hash_single_node(node);
    return node;
  }
  return new_node;
}


static bpt_merkle_node_t*
remove_element(int is_key, bpt_merkle_node_t* parent, bpt_merkle_node_t* node, int i, int j){
  int k, limit;
  if(is_key){
    limit = node->valid_num;
    for(k = j + 1;k < limit;++k){
      node->addr_pivot[k-1] = node->addr_pivot[k];
      memcpy(node->data[k-1], node->data[k], 32);
    }
    node->addr_pivot[node->valid_num-1] = unavailable;
    parent->addr_pivot[i] = node->addr_pivot[0];
    node->valid_num -= 1;
  }
  else{
    limit = parent->valid_num;
    for(k = i+1;k < limit;++k){
      parent->children[k-1] = parent->children[k];
      parent->addr_pivot[k-1] = parent->addr_pivot[k];
    }
    parent->children[parent->valid_num-1] = NULL;
    parent->addr_pivot[parent->valid_num-1] = unavailable;
    parent->valid_num -= 1;
  }
  return node;
}


// move an element from one node to its sibling
// i is the position of src in parent
// n is the number of data to be moved
static bpt_merkle_node_t*
move_element(bpt_merkle_node_t* src, bpt_merkle_node_t* dst, bpt_merkle_node_t* parent, int i, int n){
  uintptr_t tmp_key;
  uint8_t   tmp_data[32];
  bpt_merkle_node_t* child;
  int j, src_in_front;
  src_in_front = 0;
  if(src->addr_pivot[0] < dst->addr_pivot[0]){
    src_in_front = 1;
  }
  j = 0;
  if(src_in_front){
    if(!src->is_leaf){
      for(;j < n;++j){
        child = src->children[src->valid_num-1];
        remove_element(0, src, child, src->valid_num-1, unavailable);
        insert_element(0, dst, child, unavailable, NULL, 0, unavailable);
      }
    }
    else{
      for(;j < n;++j){
        tmp_key = src->addr_pivot[src->valid_num-1];
        memcpy(tmp_data, src->data[src->valid_num-1], 32);
        remove_element(1, parent, src, i, src->valid_num-1);
        insert_element(1, parent, dst, tmp_key, tmp_data, i+1, 0);
      }
    }
    parent->addr_pivot[i+1] = dst->addr_pivot[0];
  }
  else{
    if(!src->is_leaf){
      for(;j < n;++j){
        child = src->children[0];
        remove_element(0, src, child, 0, unavailable);
        insert_element(0, dst, child, unavailable, NULL, dst->valid_num, unavailable);
      }
    }
    else{
      for(;j < n;++j){
        tmp_key = src->addr_pivot[0];
        memcpy(tmp_data, src->data[0], 32);
        remove_element(1, parent, src, i, 0);
        insert_element(1, parent, dst, tmp_key, tmp_data, i-1, dst->valid_num);
      }
    }
    parent->addr_pivot[i] = src->addr_pivot[0];
  }
  return parent;
}


// find a sibling node who is not full, if not exists, return MULL
static bpt_merkle_node_t*
find_sibling(bpt_merkle_node_t* parent, int i){
  bpt_merkle_node_t* sibling = NULL;
  int limit = BPT_DEGREE;
  if(i == 0){
    if(parent->children[1]->valid_num < limit){
      sibling = parent->children[1];
    }
  }
  else if(parent->children[i-1]->valid_num < limit){
    sibling = parent->children[i-1];
  }
  else if(i + 1 < parent->valid_num && parent->children[i+1]->valid_num < limit){
    sibling = parent->children[i+1];
  }
  return sibling;
}


static bpt_merkle_node_t*
recursive_insert(bpt_merkle_node_t* node, uintptr_t key, const uint8_t hash[32], int i, bpt_merkle_node_t* parent){
  int j, limit;
  bpt_merkle_node_t* sibling;

  // search the branch

  for(j = 0;j < node->valid_num && key >= node->addr_pivot[j];++j){
    // if the key exists
    if(key == node->addr_pivot[j]){
      if(node->is_leaf){
        memcpy(node->data[j], hash, 32);
        bpt_merk_hash_single_node(node);
        return node;
      }
    }
  }

  if(j != 0 && !node->is_leaf){
    --j;
  }

  // leaf
  if(node->is_leaf){
    node = insert_element(true, parent, node, key, hash, i, j);
  }
  // branch node
  else{
    node->children[j] = recursive_insert(node->children[j], key, hash, j, node);
  }

  // adjust nodes
  limit = BPT_DEGREE;
  if(node->valid_num > limit){
    // root
    if(parent == NULL){
      // split the node
      node = split_node(parent, node, i);
    }
    else{
      sibling = find_sibling(parent, i);
      if(sibling){
        move_element(node, sibling, parent, i, 1);
      }
      else{
        sibling = split_node(parent, node, i);
      }
      bpt_merk_hash_single_node(sibling);
      bpt_merk_hash_single_node(node);
    }
  }
  else{
    bpt_merk_hash_single_node(node);
  }
  if(parent){
    parent->addr_pivot[i] = node->addr_pivot[0];
  }
  return node;
}


void
bpt_merk_insert(bpt_merkle_node_t* root, uintptr_t key, const uint8_t hash[32]){
  recursive_insert(root, key, hash, 0, NULL);
}


bool
bpt_merk_verify(bpt_merkle_node_t* root, uintptr_t key, const uint8_t hash[32]){
  bpt_merkle_node_t* curr_node = root;
  while(!curr_node->is_leaf){
    assert(bpt_merk_verify_single_node(curr_node));
    int idx;
    for(idx = 0;idx < curr_node->valid_num;++idx){
      if(key >= curr_node->addr_pivot[idx] && (idx == curr_node->valid_num-1 || key < curr_node->addr_pivot[idx+1])){
        break;
      }
    }
    curr_node = curr_node->children[idx];
  }
  assert(bpt_merk_verify_single_node(curr_node));
  int idx;
  for(idx = 0;idx < curr_node->valid_num;++idx){
    if(curr_node->addr_pivot[idx] == key){
      break;
    }
  }
  if(idx == curr_node->valid_num){
    printf("error, addr 0x%lx not found in the B+ Merkle Tree\n", key);
    return false;
  }
  int result = memcmp(hash, curr_node->data[idx], 32);
  if(result != 0){
    printf("error, leaf node hash compare failed at %d\n", result);
  }
  return result == 0;
}


static void
bpt_merk_travel_bfs(bpt_merkle_node_t* node, int level){
  printf("[BPT][%d]valid_num=%d, is_leaf=%d\n][BPT][%d]addr_pivot:", level, node->valid_num, node->is_leaf, level);
  for(int i = 0;i < node->valid_num;++i){
    printf(" %lx", node->addr_pivot[i]);
  }
  printf("\n");
  if(node->is_leaf){
    printf("\n[BPT][%d]data:", level);
    for(int i = 0;i <= node->valid_num;++i){
      printf("[BPT]\t%lx_%lx_%lx_%lx\n", *((uint64_t*)node->data[i]), *((uint64_t*)node->data[i]+1), *((uint64_t*)node->data[i]+2), *((uint64_t*)node->data[i]+3));
    }
  }
  if(!node->is_leaf){
    for(int i = 0;i < node->valid_num;++i){
      bpt_merk_travel_bfs(node->children[i], level+1);
    }
  }
}


void bpt_merk_travel(bpt_merkle_node_t* root){
  bpt_merk_travel_bfs(root, 0);
}

#endif