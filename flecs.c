#ifndef FLECS_IMPL
#include "flecs.h"
#endif
#ifndef FLECS_PRIVATE_H
#define FLECS_PRIVATE_H

#ifndef FLECS_TYPES_PRIVATE_H
#define FLECS_TYPES_PRIVATE_H

#ifndef __MACH__
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <math.h>

#ifdef _MSC_VER
//FIXME
#else
#include <sys/param.h>  /* attempt to define endianness */
#endif
#ifdef linux
# include <endian.h>    /* attempt to define endianness */
#endif

/**
 * @file entity_index.h
 * @brief Entity index data structure.
 *
 * The entity index stores the table, row for an entity id. It is implemented as
 * a sparse set. This file contains convenience macro's for working with the
 * entity index.
 */

#ifndef FLECS_ENTITY_INDEX_H
#define FLECS_ENTITY_INDEX_H

#ifdef __cplusplus
extern "C" {
#endif

#define ecs_eis_get(world, entity) ecs_sparse_get_sparse((world->store).entity_index, ecs_record_t, entity)
#define ecs_eis_get_any(world, entity) ecs_sparse_get_sparse_any((world->store).entity_index, ecs_record_t, entity)
#define ecs_eis_set(world, entity, ...) (ecs_sparse_set((world->store).entity_index, ecs_record_t, entity, (__VA_ARGS__)))
#define ecs_eis_ensure(world, entity) ecs_sparse_ensure((world->store).entity_index, ecs_record_t, entity)
#define ecs_eis_delete(world, entity) ecs_sparse_remove((world->store).entity_index, entity)
#define ecs_eis_set_generation(world, entity) ecs_sparse_set_generation((world->store).entity_index, entity)
#define ecs_eis_is_alive(world, entity) ecs_sparse_is_alive((world->store).entity_index, entity)
#define ecs_eis_get_current(world, entity) ecs_sparse_get_current((world->store).entity_index, entity)
#define ecs_eis_exists(world, entity) ecs_sparse_exists((world->store).entity_index, entity)
#define ecs_eis_recycle(world) ecs_sparse_new_id((world->store).entity_index)
#define ecs_eis_clear_entity(world, entity, is_watched) ecs_eis_set((world->store).entity_index, entity, &(ecs_record_t){NULL, is_watched})
#define ecs_eis_set_size(world, size) ecs_sparse_set_size((world->store).entity_index, size)
#define ecs_eis_count(world) ecs_sparse_count((world->store).entity_index)
#define ecs_eis_clear(world) ecs_sparse_clear((world->store).entity_index)
#define ecs_eis_copy(world) ecs_sparse_copy((world->store).entity_index)
#define ecs_eis_free(world) ecs_sparse_free((world->store).entity_index)
#define ecs_eis_memory(world, allocd, used) ecs_sparse_memory((world->store).entity_index, allocd, used)

#ifdef __cplusplus
}
#endif

#endif
/**
 * @file bitset.h
 * @brief Bitset datastructure.
 *
 * Simple bitset implementation. The bitset allows for storage of arbitrary
 * numbers of bits.
 */

#ifndef FLECS_BITSET_H
#define FLECS_BITSET_H


#ifdef __cplusplus
extern "C" {
#endif

typedef struct ecs_bitset_t {
    uint64_t *data;
    int32_t count;
    ecs_size_t size;
} ecs_bitset_t;

/** Initialize bitset. */
FLECS_DBG_API
void ecs_bitset_init(
    ecs_bitset_t *bs);

/** Deinialize bitset. */
FLECS_DBG_API
void ecs_bitset_deinit(
    ecs_bitset_t *bs);

/** Add n elements to bitset. */
FLECS_DBG_API
void ecs_bitset_addn(
    ecs_bitset_t *bs,
    int32_t count);

/** Ensure element exists. */
FLECS_DBG_API
void ecs_bitset_ensure(
    ecs_bitset_t *bs,
    int32_t count);

/** Set element. */
FLECS_DBG_API
void ecs_bitset_set(
    ecs_bitset_t *bs,
    int32_t elem,
    bool value);

/** Get element. */
FLECS_DBG_API
bool ecs_bitset_get(
    const ecs_bitset_t *bs,
    int32_t elem);

/** Return number of elements. */
FLECS_DBG_API
int32_t ecs_bitset_count(
    const ecs_bitset_t *bs);

/** Remove from bitset. */
FLECS_DBG_API
void ecs_bitset_remove(
    ecs_bitset_t *bs,
    int32_t elem);

/** Swap values in bitset. */
FLECS_DBG_API
void ecs_bitset_swap(
    ecs_bitset_t *bs,
    int32_t elem_a,
    int32_t elem_b);

#ifdef __cplusplus
}
#endif

#endif
/**
 * @file sparse.h
 * @brief Sparse set datastructure.
 *
 * This is an implementation of a paged sparse set that stores the payload in
 * the sparse array.
 *
 * A sparse set has a dense and a sparse array. The sparse array is directly
 * indexed by a 64 bit identifier. The sparse element is linked with a dense
 * element, which allows for liveliness checking. The liveliness check itself
 * can be performed by doing (psuedo code):
 *  dense[sparse[sparse_id].dense] == sparse_id
 *
 * To ensure that the sparse array doesn't have to grow to a large size when
 * using large sparse_id's, the sparse set uses paging. This cuts up the array
 * into several pages of 4096 elements. When an element is set, the sparse set
 * ensures that the corresponding page is created. The page associated with an
 * id is determined by shifting a bit 12 bits to the right.
 *
 * The sparse set keeps track of a generation count per id, which is increased
 * each time an id is deleted. The generation is encoded in the returned id.
 *
 * This sparse set implementation stores payload in the sparse array, which is
 * not typical. The reason for this is to guarantee that (in combination with
 * paging) the returned payload pointers are stable. This allows for various
 * optimizations in the parts of the framework that uses the sparse set.
 *
 * The sparse set has been designed so that new ids can be generated in bulk, in
 * an O(1) operation. The way this works is that once a dense-sparse pair is
 * created, it is never unpaired. Instead it is moved to the end of the dense
 * array, and the sparse set stores an additional count to keep track of the
 * last alive id in the sparse set. To generate new ids in bulk, the sparse set
 * only needs to increase this count by the number of requested ids.
 */

#ifndef FLECS_SPARSE_H
#define FLECS_SPARSE_H


#ifdef __cplusplus
extern "C" {
#endif

/** Create new sparse set */
FLECS_DBG_API
ecs_sparse_t* _ecs_sparse_new(
    ecs_size_t elem_size);

#define ecs_sparse_new(type)\
    _ecs_sparse_new(sizeof(type))

/** Set id source. This allows the sparse set to use an external variable for
 * issuing and increasing new ids. */
FLECS_DBG_API
void ecs_sparse_set_id_source(
    ecs_sparse_t *sparse,
    uint64_t *id_source);

/** Free sparse set */
FLECS_DBG_API
void ecs_sparse_free(
    ecs_sparse_t *sparse);

/** Remove all elements from sparse set */
FLECS_DBG_API
void ecs_sparse_clear(
    ecs_sparse_t *sparse);

/** Add element to sparse set, this generates or recycles an id */
FLECS_DBG_API
void* _ecs_sparse_add(
    ecs_sparse_t *sparse,
    ecs_size_t elem_size);

#define ecs_sparse_add(sparse, type)\
    ((type*)_ecs_sparse_add(sparse, sizeof(type)))

/** Get last issued id. */
FLECS_DBG_API
uint64_t ecs_sparse_last_id(
    ecs_sparse_t *sparse);

/** Generate or recycle a new id. */
FLECS_DBG_API
uint64_t ecs_sparse_new_id(
    ecs_sparse_t *sparse);

/** Generate or recycle new ids in bulk. The returned pointer points directly to
 * the internal dense array vector with sparse ids. Operations on the sparse set
 * can (and likely will) modify the contents of the buffer. */
FLECS_DBG_API
const uint64_t* ecs_sparse_new_ids(
    ecs_sparse_t *sparse,
    int32_t count);

/** Remove an element */
FLECS_DBG_API
void ecs_sparse_remove(
    ecs_sparse_t *sparse,
    uint64_t index);

/** Remove an element, return pointer to the value in the sparse array */
FLECS_DBG_API
void* _ecs_sparse_remove_get(
    ecs_sparse_t *sparse,
    ecs_size_t elem_size,
    uint64_t index);    

#define ecs_sparse_remove_get(sparse, type, index)\
    ((type*)_ecs_sparse_remove_get(sparse, sizeof(type), index))

/** Override the generation count for a specific id */
FLECS_DBG_API
void ecs_sparse_set_generation(
    ecs_sparse_t *sparse,
    uint64_t index);    

/** Check whether an id has ever been issued. */
FLECS_DBG_API
bool ecs_sparse_exists(
    const ecs_sparse_t *sparse,
    uint64_t index);

/** Test if id is alive, which requires the generation count tp match. */
FLECS_DBG_API
bool ecs_sparse_is_alive(
    const ecs_sparse_t *sparse,
    uint64_t index);

/** Return identifier with current generation set. */
FLECS_DBG_API
uint64_t ecs_sparse_get_current(
    const ecs_sparse_t *sparse,
    uint64_t index);

/** Get value from sparse set by dense id. This function is useful in 
 * combination with ecs_sparse_count for iterating all values in the set. */
FLECS_DBG_API
void* _ecs_sparse_get(
    const ecs_sparse_t *sparse,
    ecs_size_t elem_size,
    int32_t index);

#define ecs_sparse_get(sparse, type, index)\
    ((type*)_ecs_sparse_get(sparse, sizeof(type), index))

/** Get the number of alive elements in the sparse set. */
FLECS_DBG_API
int32_t ecs_sparse_count(
    const ecs_sparse_t *sparse);

/** Return total number of allocated elements in the dense array */
FLECS_DBG_API
int32_t ecs_sparse_size(
    const ecs_sparse_t *sparse);

/** Get element by (sparse) id. The returned pointer is stable for the duration
 * of the sparse set, as it is stored in the sparse array. */
FLECS_DBG_API
void* _ecs_sparse_get_sparse(
    const ecs_sparse_t *sparse,
    ecs_size_t elem_size,
    uint64_t index);

#define ecs_sparse_get_sparse(sparse, type, index)\
    ((type*)_ecs_sparse_get_sparse(sparse, sizeof(type), index))

/** Like get_sparse, but don't care whether element is alive or not. */
FLECS_DBG_API
void* _ecs_sparse_get_sparse_any(
    ecs_sparse_t *sparse,
    ecs_size_t elem_size,
    uint64_t index);

#define ecs_sparse_get_sparse_any(sparse, type, index)\
    ((type*)_ecs_sparse_get_sparse_any(sparse, sizeof(type), index))

/** Get or create element by (sparse) id. */
FLECS_DBG_API
void* _ecs_sparse_ensure(
    ecs_sparse_t *sparse,
    ecs_size_t elem_size,
    uint64_t index);

#define ecs_sparse_ensure(sparse, type, index)\
    ((type*)_ecs_sparse_ensure(sparse, sizeof(type), index))

/** Set value. */
FLECS_DBG_API
void* _ecs_sparse_set(
    ecs_sparse_t *sparse,
    ecs_size_t elem_size,
    uint64_t index,
    void *value);

#define ecs_sparse_set(sparse, type, index, value)\
    ((type*)_ecs_sparse_set(sparse, sizeof(type), index, value))

/** Get pointer to ids (alive and not alive). Use with count() or size(). */
FLECS_DBG_API
const uint64_t* ecs_sparse_ids(
    const ecs_sparse_t *sparse);

/** Set size of the dense array. */
FLECS_DBG_API
void ecs_sparse_set_size(
    ecs_sparse_t *sparse,
    int32_t elem_count);

/** Copy sparse set into a new sparse set. */
FLECS_DBG_API
ecs_sparse_t* ecs_sparse_copy(
    const ecs_sparse_t *src);    

/** Restore sparse set into destination sparse set. */
FLECS_DBG_API
void ecs_sparse_restore(
    ecs_sparse_t *dst,
    const ecs_sparse_t *src);

/** Get memory usage of sparse set. */
FLECS_DBG_API
void ecs_sparse_memory(
    ecs_sparse_t *sparse,
    int32_t *allocd,
    int32_t *used);

#ifndef FLECS_LEGACY
#define ecs_sparse_each(sparse, T, var, ...)\
    {\
        int var##_i, var##_count = ecs_sparse_count(sparse);\
        for (var##_i = 0; var##_i < var##_count; var##_i ++) {\
            T* var = ecs_sparse_get(sparse, T, var##_i);\
            __VA_ARGS__\
        }\
    }
#endif

#ifdef __cplusplus
}
#endif

#endif
/**
 * @file switch_list.h
 * @brief Interleaved linked list for storing mutually exclusive values.
 *
 * Datastructure that stores N interleaved linked lists in an array. 
 * This allows for efficient storage of elements with mutually exclusive values.
 * Each linked list has a header element which points to the index in the array
 * that stores the first node of the list. Each list node points to the next
 * array element.
 *
 * The datastructure needs to be created with min and max values, so that it can
 * allocate an array of headers that can be directly indexed by the value. The
 * values are stored in a contiguous array, which allows for the values to be
 * iterated without having to follow the linked list nodes.
 *
 * The datastructure allows for efficient storage and retrieval for values with
 * mutually exclusive values, such as enumeration values. The linked list allows
 * an application to obtain all elements for a given (enumeration) value without
 * having to search.
 *
 * While the list accepts 64 bit values, it only uses the lower 32bits of the
 * value for selecting the correct linked list.
 */

#ifndef FLECS_SWITCH_LIST_H
#define FLECS_SWITCH_LIST_H


typedef struct ecs_switch_header_t {
    int32_t element;        /* First element for value */
    int32_t count;          /* Number of elements for value */
} ecs_switch_header_t;

typedef struct ecs_switch_node_t {
    int32_t next;           /* Next node in list */
    int32_t prev;           /* Prev node in list */
} ecs_switch_node_t;

struct ecs_switch_t {
    uint64_t min;           /* Minimum value the switch can store */
    uint64_t max;           /* Maximum value the switch can store */
    ecs_switch_header_t *headers;   /* Array with headers, indexed by value */
    ecs_vector_t *nodes;    /* Vector with nodes, of type ecs_switch_node_t */
    ecs_vector_t *values;   /* Vector with values, of type uint64_t */
};

/** Create new switch. */
FLECS_DBG_API
ecs_switch_t* ecs_switch_new(
    uint64_t min, 
    uint64_t max,
    int32_t elements);

/** Free switch. */
FLECS_DBG_API
void ecs_switch_free(
    ecs_switch_t *sw);

/** Add element to switch, initialize value to 0 */
FLECS_DBG_API
void ecs_switch_add(
    ecs_switch_t *sw);

/** Set number of elements in switch list */
FLECS_DBG_API
void ecs_switch_set_count(
    ecs_switch_t *sw,
    int32_t count);

/** Ensure that element exists. */
FLECS_DBG_API
void ecs_switch_ensure(
    ecs_switch_t *sw,
    int32_t count);

/** Add n elements. */
FLECS_DBG_API
void ecs_switch_addn(
    ecs_switch_t *sw,
    int32_t count);    

/** Set value of element. */
FLECS_DBG_API
void ecs_switch_set(
    ecs_switch_t *sw,
    int32_t element,
    uint64_t value);

/** Remove element. */
FLECS_DBG_API
void ecs_switch_remove(
    ecs_switch_t *sw,
    int32_t element);

/** Get value for element. */
FLECS_DBG_API
uint64_t ecs_switch_get(
    const ecs_switch_t *sw,
    int32_t element);

/** Swap element. */
FLECS_DBG_API
void ecs_switch_swap(
    ecs_switch_t *sw,
    int32_t elem_1,
    int32_t elem_2);

/** Get vector with all values. Use together with count(). */
FLECS_DBG_API
ecs_vector_t* ecs_switch_values(
    const ecs_switch_t *sw);    

/** Return number of different values. */
FLECS_DBG_API
int32_t ecs_switch_case_count(
    const ecs_switch_t *sw,
    uint64_t value);

/** Return first element for value. */
FLECS_DBG_API
int32_t ecs_switch_first(
    const ecs_switch_t *sw,
    uint64_t value);

/** Return next element for value. Use with first(). */
FLECS_DBG_API
int32_t ecs_switch_next(
    const ecs_switch_t *sw,
    int32_t elem);

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif

#define ECS_MAX_JOBS_PER_WORKER (16)

/** These values are used to verify validity of the pointers passed into the API
 * and to allow for passing a thread as a world to some API calls (this allows
 * for transparently passing thread context to API functions) */
#define ECS_WORLD_MAGIC (0x65637377)
#define ECS_STAGE_MAGIC (0x65637374)

/* Maximum number of entities that can be added in a single operation. 
 * Increasing this value will increase consumption of stack space. */
#define ECS_MAX_ADD_REMOVE (32)

/* Maximum length of an entity name, including 0 terminator */
#define ECS_MAX_NAME_LENGTH (64)

/** Component-specific data */
typedef struct ecs_type_info_t {
    ecs_entity_t component;
    ecs_vector_t *on_add;       /* Systems ran after adding this component */
    ecs_vector_t *on_remove;    /* Systems ran after removing this component */
    EcsComponentLifecycle lifecycle; /* Component lifecycle callbacks */
    bool lifecycle_set;
} ecs_type_info_t;

/* Table event type for notifying tables of world events */
typedef enum ecs_table_eventkind_t {
    EcsTableQueryMatch,
    EcsTableQueryUnmatch,
    EcsTableTriggerMatch,
    EcsTableComponentInfo
} ecs_table_eventkind_t;

typedef struct ecs_table_event_t {
    ecs_table_eventkind_t kind;

    /* Query event */
    ecs_query_t *query;
    int32_t matched_table_index;

    /* Component info event */
    ecs_entity_t component;

    /* Trigger match */
    ecs_entity_t event;

    /* If the nubmer of fields gets out of hand, this can be turned into a union
     * but since events are very temporary objects, this works for now and makes
     * initializing an event a bit simpler. */
} ecs_table_event_t;    

/** A component column. */
struct ecs_column_t {
    ecs_vector_t *data;        /**< Column data */
    int16_t size;              /**< Column element size */
    int16_t alignment;         /**< Column element alignment */
};

/** A switch column. */
typedef struct ecs_sw_column_t {
    ecs_switch_t *data;   /**< Column data */
    ecs_type_t type;      /**< Switch type */
} ecs_sw_column_t;

/** A bitset column. */
typedef struct ecs_bs_column_t {
    ecs_bitset_t data;   /**< Column data */
} ecs_bs_column_t;

/** Stage-specific component data */
struct ecs_data_t {
    ecs_vector_t *entities;      /**< Entity identifiers */
    ecs_vector_t *record_ptrs;   /**< Ptrs to records in main entity index */
    ecs_column_t *columns;       /**< Component columns */
    ecs_sw_column_t *sw_columns; /**< Switch columns */
    ecs_bs_column_t *bs_columns; /**< Bitset columns */
};

/** Small footprint data structure for storing data associated with a table. */
typedef struct ecs_table_leaf_t {
    ecs_table_t *table;
    ecs_type_t type;
    ecs_data_t *data;
} ecs_table_leaf_t;

/** Flags for quickly checking for special properties of a table. */
#define EcsTableHasBuiltins         1u    /**< Does table have builtin components */
#define EcsTableIsPrefab            2u    /**< Does the table store prefabs */
#define EcsTableHasBase             4u    /**< Does the table type has IsA */
#define EcsTableHasParent           8u    /**< Does the table type has ChildOf */
#define EcsTableHasComponentData    16u   /**< Does the table have component data */
#define EcsTableHasXor              32u   /**< Does the table type has XOR */
#define EcsTableIsDisabled          64u   /**< Does the table type has EcsDisabled */
#define EcsTableHasCtors            128u
#define EcsTableHasDtors            256u
#define EcsTableHasCopy             512u
#define EcsTableHasMove             1024u
#define EcsTableHasOnAdd            2048u
#define EcsTableHasOnRemove         4096u
#define EcsTableHasOnSet            8192u
#define EcsTableHasUnSet            16384u
#define EcsTableHasMonitors         32768u
#define EcsTableHasSwitch           65536u
#define EcsTableHasDisabled         131072u

/* Composite constants */
#define EcsTableHasLifecycle        (EcsTableHasCtors | EcsTableHasDtors)
#define EcsTableIsComplex           (EcsTableHasLifecycle | EcsTableHasSwitch | EcsTableHasDisabled)
#define EcsTableHasAddActions       (EcsTableHasBase | EcsTableHasSwitch | EcsTableHasCtors | EcsTableHasOnAdd | EcsTableHasOnSet | EcsTableHasMonitors)
#define EcsTableHasRemoveActions    (EcsTableHasBase | EcsTableHasDtors | EcsTableHasOnRemove | EcsTableHasUnSet | EcsTableHasMonitors)

/** Edge used for traversing the table graph. */
typedef struct ecs_edge_t {
    ecs_table_t *add;               /**< Edges traversed when adding */
    ecs_table_t *remove;            /**< Edges traversed when removing */
} ecs_edge_t;

/** Quey matched with table with backref to query table administration.
 * This type is used to store a matched query together with the array index of
 * where the table is stored in the query administration. This type is used when
 * an action that originates on a table needs to invoke a query (system) and a
 * fast lookup is required for the query administration, as is the case with
 * OnSet and Monitor systems. */
typedef struct ecs_matched_query_t {
    ecs_query_t *query;             /**< The query matched with the table */
    int32_t matched_table_index;    /**< Table index in the query type */
} ecs_matched_query_t;

/** A table is the Flecs equivalent of an archetype. Tables store all entities
 * with a specific set of components. Tables are automatically created when an
 * entity has a set of components not previously observed before. When a new
 * table is created, it is automatically matched with existing queries */
struct ecs_table_t {
    ecs_type_t type;                 /**< Identifies table type in type_index */
    ecs_type_info_t **c_info;           /**< Cached pointers to component info */

    ecs_edge_t *lo_edges;            /**< Edges to other tables */
    ecs_map_t *hi_edges;

    ecs_data_t *data;                /**< Component storage */

    ecs_vector_t *queries;           /**< Queries matched with table */
    ecs_vector_t *monitors;          /**< Monitor systems matched with table */
    ecs_vector_t **on_set;           /**< OnSet systems, broken up by column */
    ecs_vector_t *on_set_all;        /**< All OnSet systems */
    ecs_vector_t *on_set_override;   /**< All OnSet systems with overrides */
    ecs_vector_t *un_set_all;        /**< All UnSet systems */

    int32_t *dirty_state;            /**< Keep track of changes in columns */
    int32_t alloc_count;             /**< Increases when columns are reallocd */
    uint64_t id;                     /**< Table id in sparse set */

    ecs_flags32_t flags;             /**< Flags for testing table properties */
    
    int32_t column_count;            /**< Number of data columns in table */
    int32_t sw_column_count;
    int32_t sw_column_offset;
    int32_t bs_column_count;
    int32_t bs_column_offset;
};

/* Sparse query column */
typedef struct ecs_sparse_column_t {
    ecs_sw_column_t *sw_column;
    ecs_entity_t sw_case; 
    int32_t signature_column_index;
} ecs_sparse_column_t;

/* Bitset query column */
typedef struct ecs_bitset_column_t {
    ecs_bs_column_t *bs_column;
    int32_t column_index;
} ecs_bitset_column_t;

/** Type containing data for a table matched with a query. */
typedef struct ecs_matched_table_t {
    ecs_iter_table_t iter_data;    /**< Precomputed data for iterators */
    ecs_vector_t *sparse_columns;  /**< Column ids of sparse columns */
    ecs_vector_t *bitset_columns;  /**< Column ids with disabled flags */
    int32_t *monitor;              /**< Used to monitor table for changes */
    int32_t rank;                  /**< Rank used to sort tables */
} ecs_matched_table_t;

/** Type used to track location of table in queries' table lists.
 * When a table becomes empty or non-empty a signal is sent to a query, which
 * moves the table to or from an empty list. While this ensures that when 
 * iterating no time is spent on iterating over empty tables, doing a linear
 * search for the table in either list can take a significant amount of time if
 * a query is matched with many tables.
 *
 * To avoid a linear search, the query has a map with table indices that can
 * return the location of the table in either list in constant time.
 *
 * If a table is matched multiple times by a query, such as can happen when a
 * query matches pairs, a table can occupy multiple indices.
 */
typedef struct ecs_table_indices_t {
    int32_t *indices; /* If indices are negative, table is in empty list */
    int32_t count;
} ecs_table_indices_t;

/** Type storing an entity range within a table.
 * This type is used for iterating in orer across archetypes. A sorting function
 * constructs a list of the ranges across archetypes that are in order so that
 * when the query iterates over the archetypes, it only needs to iterate the
 * list of ranges. */
typedef struct ecs_table_slice_t {
    ecs_matched_table_t *table;     /**< Reference to the matched table */
    int32_t start_row;              /**< Start of range  */
    int32_t count;                  /**< Number of entities in range */
} ecs_table_slice_t;

#define EcsQueryNeedsTables (1)      /* Query needs matching with tables */ 
#define EcsQueryMonitor (2)          /* Query needs to be registered as a monitor */
#define EcsQueryOnSet (4)            /* Query needs to be registered as on_set system */
#define EcsQueryUnSet (8)            /* Query needs to be registered as un_set system */
#define EcsQueryMatchDisabled (16)   /* Does query match disabled */
#define EcsQueryMatchPrefab (32)     /* Does query match prefabs */
#define EcsQueryHasRefs (64)         /* Does query have references */
#define EcsQueryHasTraits (128)      /* Does query have pairs */
#define EcsQueryIsSubquery (256)     /* Is query a subquery */
#define EcsQueryIsOrphaned (512)     /* Is subquery orphaned */
#define EcsQueryHasOutColumns (1024) /* Does query have out columns */
#define EcsQueryHasOptional (2048)   /* Does query have optional columns */

#define EcsQueryNoActivation (EcsQueryMonitor | EcsQueryOnSet | EcsQueryUnSet)

/* Query event type for notifying queries of world events */
typedef enum ecs_query_eventkind_t {
    EcsQueryTableMatch,
    EcsQueryTableEmpty,
    EcsQueryTableNonEmpty,
    EcsQueryTableRematch,
    EcsQueryTableUnmatch,
    EcsQueryOrphan
} ecs_query_eventkind_t;

typedef struct ecs_query_event_t {
    ecs_query_eventkind_t kind;
    ecs_table_t *table;
    ecs_query_t *parent_query;
} ecs_query_event_t;

/** Query that is automatically matched against active tables */
struct ecs_query_t {
    /* Signature of query */
    ecs_filter_t filter;

    /* Reference to world */
    ecs_world_t *world;

    /* Tables matched with query */
    ecs_vector_t *tables;
    ecs_vector_t *empty_tables;
    ecs_map_t *table_indices;

    /* Handle to system (optional) */
    ecs_entity_t system;   

    /* Used for sorting */
    ecs_entity_t sort_on_component;
    ecs_compare_action_t compare;   
    ecs_vector_t *table_slices;     

    /* Used for table sorting */
    ecs_entity_t rank_on_component;
    ecs_rank_type_action_t group_table;

    /* Subqueries */
    ecs_query_t *parent;
    ecs_vector_t *subqueries;

    /* The query kind determines how it is registered with tables */
    ecs_flags32_t flags;

    uint64_t id;                /* Id of query in query storage */
    int32_t cascade_by;         /* Identify CASCADE column */
    int32_t match_count;        /* How often have tables been (un)matched */
    int32_t prev_match_count;   /* Used to track if sorting is needed */

    bool needs_reorder;         /* Whether next iteration should reorder */
    bool constraints_satisfied; /* Are all term constraints satisfied */
};

/** Event mask */
#define EcsEventAdd    (1)
#define EcsEventRemove (2)

/** Triggers for a specific id */
typedef struct ecs_id_trigger_t {
    ecs_map_t *on_add_triggers;
    ecs_map_t *on_remove_triggers;
} ecs_id_trigger_t;

/** Keep track of how many [in] columns are active for [out] columns of OnDemand
 * systems. */
typedef struct ecs_on_demand_out_t {
    ecs_entity_t system;    /* Handle to system */
    int32_t count;         /* Total number of times [out] columns are used */
} ecs_on_demand_out_t;

/** Keep track of which OnDemand systems are matched with which [in] columns */
typedef struct ecs_on_demand_in_t {
    int32_t count;         /* Number of active systems with [in] column */
    ecs_vector_t *systems;  /* Systems that have this column as [out] column */
} ecs_on_demand_in_t;

/** Types for deferred operations */
typedef enum ecs_op_kind_t {
    EcsOpNew,
    EcsOpClone,
    EcsOpBulkNew,
    EcsOpAdd,
    EcsOpRemove,   
    EcsOpSet,
    EcsOpMut,
    EcsOpModified,
    EcsOpDelete,
    EcsOpClear,
    EcsOpEnable,
    EcsOpDisable
} ecs_op_kind_t;

typedef struct ecs_op_1_t {
    ecs_entity_t entity;        /* Entity id */
    void *value;                /* Value (used for set / get_mut) */
    ecs_size_t size;            /* Size of value */
    bool clone_value;           /* Clone entity with value (used for clone) */ 
} ecs_op_1_t;

typedef struct ecs_op_n_t {
    ecs_entity_t *entities;  
    void **bulk_data;
    int32_t count;
} ecs_op_n_t;

typedef struct ecs_op_t {
    ecs_op_kind_t kind;         /* Operation kind */
    ecs_entity_t scope;         /* Scope of operation (for new) */       
    ecs_entity_t component;     /* Single component (components.count = 1) */
    ecs_entities_t components;  /* Multiple components */
    union {
        ecs_op_1_t _1;
        ecs_op_n_t _n;
    } is;
} ecs_op_t;

/** A stage is a data structure in which delta's are stored until it is safe to
 * merge those delta's with the main world stage. A stage allows flecs systems
 * to arbitrarily add/remove/set components and create/delete entities while
 * iterating. Additionally, worker threads have their own stage that lets them
 * mutate the state of entities without requiring locks. */
struct ecs_stage_t {
    int32_t magic;              /* Magic number to verify thread pointer */
    int32_t id;                 /* Unique id that identifies the stage */

    /* Are operations deferred? */
    int32_t defer;
    ecs_vector_t *defer_queue;

    ecs_world_t *thread_ctx;    /* Points to stage when a thread stage */
    ecs_world_t *world;         /* Reference to world */
    ecs_os_thread_t thread;     /* Thread handle (0 if no threading is used) */

    /* One-shot actions to be executed after the merge */
    ecs_vector_t *post_frame_actions;

    /* Namespacing */
    ecs_table_t *scope_table;      /* Table for current scope */
    ecs_entity_t scope;            /* Entity of current scope */

    /* Properties */
    bool auto_merge;               /* Should this stage automatically merge? */
    bool asynchronous;             /* Is stage asynchronous? (write only) */
};

/* Component monitor */
typedef struct ecs_monitor_t {
    ecs_vector_t *queries;  /* vector<ecs_query_t*> */
    bool is_dirty;          /* Should queries be rematched? */
} ecs_monitor_t;

/* Component monitors */
typedef struct ecs_monitor_set_t {
    ecs_map_t *monitors; /* map<id, ecs_monitor_t> */
    bool is_dirty;       /* Should monitors be evaluated? */
} ecs_monitor_set_t;

/* Relation monitors. TODO: implement generic monitor mechanism */
typedef struct ecs_relation_monitor_t {
    ecs_map_t *monitor_sets; /* map<relation_id, ecs_monitor_set_t> */
    bool is_dirty;          /* Should monitor sets be evaluated? */
} ecs_relation_monitor_t;

/* Payload for table index which returns all tables for a given component, with
 * the column of the component in the table. */
typedef struct ecs_table_record_t {
    ecs_table_t *table;
    int32_t column;
} ecs_table_record_t;

/* Payload for id index which contains all datastructures for an id. */
typedef struct ecs_id_record_t {
    /* All tables that contain the id */
    ecs_map_t *table_index;         /* map<table_id, ecs_table_record_t> */
    ecs_entity_t on_delete;         /* Cleanup action for removing id */
    ecs_entity_t on_delete_object;  /* Cleanup action for removing object */
} ecs_id_record_t;

typedef struct ecs_store_t {
    /* Entity lookup */
    ecs_sparse_t *entity_index; /* sparse<entity, ecs_record_t> */

    /* Table lookup by id */
    ecs_sparse_t *tables; /* sparse<table_id, ecs_table_t> */

    /* Table lookup by hash */
    ecs_map_t *table_map; /* map<component_hash, vector<ecs_table_t*>> */  

    /* Root table */
    ecs_table_t root;
} ecs_store_t;

/** Supporting type to store looked up or derived entity data */
typedef struct ecs_entity_info_t {
    ecs_record_t *record;       /* Main stage record in entity index */
    ecs_table_t *table;         /* Table. Not set if entity is empty */
    ecs_data_t *data;           /* Stage-specific table columns */
    int32_t row;                /* Actual row (stripped from is_watched bit) */
    bool is_watched;            /* Is entity being watched */
} ecs_entity_info_t;

/** Supporting type to store looked up component data in specific table */
typedef struct ecs_column_info_t {
    ecs_entity_t id;
    const ecs_type_info_t *ci;
    int32_t column;
} ecs_column_info_t;

/* fini actions */
typedef struct ecs_action_elem_t {
    ecs_fini_action_t action;
    void *ctx;
} ecs_action_elem_t;

/* Alias */
typedef struct ecs_alias_t {
    char *name;
    ecs_entity_t entity;
} ecs_alias_t;

/** The world stores and manages all ECS data. An application can have more than
 * one world, but data is not shared between worlds. */
struct ecs_world_t {
    int32_t magic;               /* Magic number to verify world pointer */
    void *context;               /* Application context */
    ecs_vector_t *fini_actions;  /* Callbacks to execute when world exits */

    /* Is entity range checking enabled? */
    bool range_check_enabled;


    /* --  Type metadata -- */

    ecs_sparse_t *type_info;     /* sparse<type_id, type_info_t> */
    ecs_map_t *id_index;         /* map<id, ecs_id_record_t> */
    ecs_map_t *id_triggers;      /* map<id, ecs_id_trigger_t> */


    /* --  Data storage -- */

    ecs_store_t store;


    /* --  Storages for opaque API objects -- */

    ecs_sparse_t *queries; /* sparse<query_id, ecs_query_t> */
    ecs_sparse_t *triggers; /* sparse<query_id, ecs_query_t> */
    

    /* Keep track of components that were added/removed to/from monitored
     * entities. Monitored entities are entities that a query has matched with
     * specifically, as is the case with PARENT / CASCADE columns, FromEntity
     * columns and columns matched from prefabs. 
     * When these entities change type, queries may have to be rematched.
     * Queries register themselves as component monitors for specific components
     * and when these components change they are rematched. The component 
     * monitors are evaluated during a merge. */
    ecs_relation_monitor_t monitors;

    /* -- Systems -- */
    
    ecs_entity_t pipeline;             /* Current pipeline */
    ecs_map_t *on_activate_components; /* Trigger on activate of [in] column */
    ecs_map_t *on_enable_components;   /* Trigger on enable of [in] column */
    ecs_vector_t *fini_tasks;          /* Tasks to execute on ecs_fini */


    /* -- Lookup Indices -- */

    ecs_map_t *type_handles;          /* Handles to named types */


    /* -- Aliasses -- */

    ecs_vector_t *aliases;


    /* -- Staging -- */

    ecs_stage_t stage;               /* Main storage */
    ecs_vector_t *worker_stages;     /* Stages for threads */


    /* -- Hierarchy administration -- */

    const char *name_prefix;        /* Remove prefix from C names in modules */


    /* -- Multithreading -- */

    ecs_os_cond_t worker_cond;       /* Signal that worker threads can start */
    ecs_os_cond_t sync_cond;         /* Signal that worker thread job is done */
    ecs_os_mutex_t sync_mutex;       /* Mutex for job_cond */
    int32_t workers_running;         /* Number of threads running */
    int32_t workers_waiting;         /* Number of workers waiting on sync */


    /* -- Time management -- */

    ecs_time_t world_start_time;  /* Timestamp of simulation start */
    ecs_time_t frame_start_time;  /* Timestamp of frame start */
    FLECS_FLOAT fps_sleep;        /* Sleep time to prevent fps overshoot */


    /* -- Metrics -- */

    ecs_world_info_t stats;


    /* -- Settings from command line arguments -- */

    int arg_fps;
    int arg_threads;


    /* -- World lock -- */

    ecs_os_mutex_t mutex;         /* Locks the world if locking enabled */
    ecs_os_mutex_t thr_sync;      /* Used to signal threads at end of frame */
    ecs_os_cond_t thr_cond;       /* Used to signal threads at end of frame */


    /* -- Defered operation count -- */
    
    int32_t new_count;
    int32_t bulk_new_count;
    int32_t delete_count;
    int32_t clear_count;
    int32_t add_count;
    int32_t remove_count;
    int32_t set_count;
    int32_t discard_count;


    /* -- World state -- */

    bool quit_workers;            /* Signals worker threads to quit */
    bool is_readonly;             /* Is world being progressed */
    bool is_fini;                 /* Is the world being cleaned up? */
    bool measure_frame_time;      /* Time spent on each frame */
    bool measure_system_time;     /* Time spent by each system */
    bool should_quit;             /* Did a system signal that app should quit */
    bool locking_enabled;         /* Lock world when in progress */    
};

#endif

////////////////////////////////////////////////////////////////////////////////
//// Core bootstrap functions
////////////////////////////////////////////////////////////////////////////////

#define ECS_TYPE_DECL(component)\
static const ecs_entity_t __##component = ecs_id(component);\
ECS_VECTOR_DECL(FLECS__T##component, ecs_entity_t, 1)

#define ECS_TYPE_IMPL(component)\
ECS_VECTOR_IMPL(FLECS__T##component, ecs_entity_t, &__##component, 1)

/* Bootstrap world */
void ecs_bootstrap(
    ecs_world_t *world);

ecs_type_t ecs_bootstrap_type(
    ecs_world_t *world,
    ecs_entity_t entity);

#define ecs_bootstrap_component(world, id)\
    ecs_component_init(world, &(ecs_component_desc_t){\
        .entity = {\
            .entity = ecs_id(id),\
            .name = #id,\
            .symbol = #id\
        },\
        .size = sizeof(id),\
        .alignment = ECS_ALIGNOF(id)\
    });

#define ecs_bootstrap_tag(world, name)\
    ecs_set(world, name, EcsName, {.value = &#name[ecs_os_strlen("Ecs")], .symbol = (char*)#name});\
    ecs_add_pair(world, name, EcsChildOf, ecs_get_scope(world))


////////////////////////////////////////////////////////////////////////////////
//// Entity API
////////////////////////////////////////////////////////////////////////////////

/* Mark an entity as being watched. This is used to trigger automatic rematching
 * when entities used in system expressions change their components. */
void ecs_set_watch(
    ecs_world_t *world,
    ecs_entity_t entity);

/* Does one of the entity containers has specified component */
ecs_entity_t ecs_find_in_type(
    const ecs_world_t *world,
    ecs_type_t table_type,
    ecs_entity_t component,
    ecs_entity_t flags);

/* Obtain entity info */
bool ecs_get_info(
    const ecs_world_t *world,
    ecs_entity_t entity,
    ecs_entity_info_t *info);

void ecs_run_monitors(
    ecs_world_t *world, 
    ecs_table_t *dst_table,
    ecs_vector_t *v_dst_monitors, 
    int32_t dst_row, 
    int32_t count, 
    ecs_vector_t *v_src_monitors);


////////////////////////////////////////////////////////////////////////////////
//// World API
////////////////////////////////////////////////////////////////////////////////

/* Notify systems that there is a new table, which triggers matching */
void ecs_notify_queries_of_table(
    ecs_world_t *world,
    ecs_table_t *table);

/* Get current stage */
ecs_stage_t* ecs_stage_from_world(
    ecs_world_t **world_ptr);

/* Get current thread-specific stage from readonly world */
const ecs_stage_t* ecs_stage_from_readonly_world(
    const ecs_world_t *world);

/* Get component callbacks */
const ecs_type_info_t *ecs_get_c_info(
    const ecs_world_t *world,
    ecs_entity_t component);

/* Get or create component callbacks */
ecs_type_info_t * ecs_get_or_create_c_info(
    ecs_world_t *world,
    ecs_entity_t component);

void ecs_eval_component_monitors(
    ecs_world_t *world);

void ecs_monitor_mark_dirty(
    ecs_world_t *world,
    ecs_entity_t relation,
    ecs_entity_t id);

void ecs_monitor_register(
    ecs_world_t *world,
    ecs_entity_t relation,
    ecs_entity_t id,
    ecs_query_t *query);

void ecs_notify_tables(
    ecs_world_t *world,
    ecs_id_t id,
    ecs_table_event_t *event);

void ecs_notify_queries(
    ecs_world_t *world,
    ecs_query_event_t *event);

void ecs_register_table(
    ecs_world_t *world,
    ecs_table_t *table);

void ecs_unregister_table(
    ecs_world_t *world,
    ecs_table_t *table);

ecs_id_record_t* ecs_ensure_id_record(
    const ecs_world_t *world,
    ecs_id_t id);

ecs_id_record_t* ecs_get_id_record(
    const ecs_world_t *world,
    ecs_id_t id);

void ecs_clear_id_record(
    const ecs_world_t *world,
    ecs_id_t id);

void ecs_triggers_notify(
    ecs_world_t *world,
    ecs_id_t id,
    ecs_entity_t event,
    ecs_table_t *table,
    ecs_data_t *data,
    int32_t row,
    int32_t count);

ecs_map_t* ecs_triggers_get(
    const ecs_world_t *world,
    ecs_id_t id,
    ecs_entity_t event);

void ecs_trigger_fini(
    ecs_world_t *world,
    ecs_trigger_t *trigger);

////////////////////////////////////////////////////////////////////////////////
//// Stage API
////////////////////////////////////////////////////////////////////////////////

/* Initialize stage data structures */
void ecs_stage_init(
    ecs_world_t *world,
    ecs_stage_t *stage);

/* Deinitialize stage */
void ecs_stage_deinit(
    ecs_world_t *world,
    ecs_stage_t *stage);

/* Post-frame merge actions */
void ecs_stage_merge_post_frame(
    ecs_world_t *world,
    ecs_stage_t *stage);  

/* Delete table from stage */
void ecs_delete_table(
    ecs_world_t *world,
    ecs_table_t *table);

////////////////////////////////////////////////////////////////////////////////
//// Defer API
////////////////////////////////////////////////////////////////////////////////

bool ecs_defer_none(
    ecs_world_t *world,
    ecs_stage_t *stage);

bool ecs_defer_modified(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity,
    ecs_entity_t component);

bool ecs_defer_new(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity,
    ecs_entities_t *components);

bool ecs_defer_clone(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity,
    ecs_entity_t src,
    bool clone_value);

bool ecs_defer_bulk_new(
    ecs_world_t *world,
    ecs_stage_t *stage,
    int32_t count,
    const ecs_entities_t *components,
    void **component_data,
    const ecs_entity_t **ids_out);

bool ecs_defer_delete(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity);

bool ecs_defer_clear(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity);

bool ecs_defer_enable(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity,
    ecs_entity_t component,
    bool enable);    

bool ecs_defer_add(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity,
    ecs_entities_t *components);

bool ecs_defer_remove(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity,
    ecs_entities_t *components);

bool ecs_defer_set(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_op_kind_t op_kind,
    ecs_entity_t entity,
    ecs_entity_t component,
    ecs_size_t size,
    const void *value,
    void **value_out,
    bool *is_added);

bool ecs_defer_flush(
    ecs_world_t *world,
    ecs_stage_t *stage);

////////////////////////////////////////////////////////////////////////////////
//// Type API
////////////////////////////////////////////////////////////////////////////////

/* Merge add/remove types */
ecs_type_t ecs_type_merge_intern(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_type_t cur_id,
    ecs_type_t to_add_id,
    ecs_type_t to_remove_id);

/* Test if type_id_1 contains type_id_2 */
ecs_entity_t ecs_type_contains(
    const ecs_world_t *world,
    ecs_type_t type_id_1,
    ecs_type_t type_id_2,
    bool match_all,
    bool match_prefab);

/* Add component to type */
ecs_type_t ecs_type_add_intern(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_type_t type,
    ecs_entity_t component);

/* Find entity in prefabs of type */
ecs_entity_t ecs_find_entity_in_prefabs(
    const ecs_world_t *world,
    ecs_entity_t entity,
    ecs_type_t type,
    ecs_entity_t component,
    ecs_entity_t previous);

void ecs_get_column_info(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_entities_t *components,
    ecs_column_info_t *cinfo,
    bool get_all);

void ecs_run_add_actions(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data,
    int32_t row,
    int32_t count,
    ecs_entities_t *added,
    bool get_all,
    bool run_on_set);   

void ecs_run_remove_actions(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data,
    int32_t row,
    int32_t count,
    ecs_entities_t *removed);

void ecs_run_set_systems(
    ecs_world_t *world,
    ecs_entities_t *components,
    ecs_table_t *table,
    ecs_data_t *data,
    int32_t row,
    int32_t count,
    bool set_all);


////////////////////////////////////////////////////////////////////////////////
//// Table API
////////////////////////////////////////////////////////////////////////////////

/** Find or create table for a set of components */
ecs_table_t* ecs_table_find_or_create(
    ecs_world_t *world,
    ecs_entities_t *type);   

/* Get table data */
ecs_data_t *ecs_table_get_data(
    const ecs_table_t *table);

/* Get or create data */
ecs_data_t *ecs_table_get_or_create_data(
    ecs_table_t *table);

/* Initialize columns for data */
ecs_data_t* ecs_init_data(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *result); 

/* Activates / deactivates table for systems. A deactivated table will not be
 * evaluated when the system is invoked. Tables automatically get activated /
 * deactivated when they become non-empty / empty. 
 *
 * If a query is provided, the table will only be activated / deactivated for
 * that query. */
void ecs_table_activate(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_query_t *query,
    bool activate);

/* Clear all entities from a table. */
void ecs_table_clear(
    ecs_world_t *world,
    ecs_table_t *table);

/* Reset a table to its initial state */
void ecs_table_reset(
    ecs_world_t *world,
    ecs_table_t *table);

/* Clear all entities from the table. Do not invoke OnRemove systems */
void ecs_table_clear_silent(
    ecs_world_t *world,
    ecs_table_t *table);

/* Clear table data. Don't call OnRemove handlers. */
void ecs_table_clear_data(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data);    

/* Return number of entities in data */
int32_t ecs_table_data_count(
    const ecs_data_t *data);

/* Add a new entry to the table for the specified entity */
int32_t ecs_table_append(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data,
    ecs_entity_t entity,
    ecs_record_t *record,
    bool construct);

/* Delete an entity from the table. */
void ecs_table_delete(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data,
    int32_t index,
    bool destruct);

/* Move a row from one table to another */
void ecs_table_move(
    ecs_world_t *world,
    ecs_entity_t dst_entity,
    ecs_entity_t src_entity,
    ecs_table_t *new_table,
    ecs_data_t *new_data,
    int32_t new_index,
    ecs_table_t *old_table,
    ecs_data_t *old_data,
    int32_t old_index);

/* Grow table with specified number of records. Populate table with entities,
 * starting from specified entity id. */
int32_t ecs_table_appendn(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data,
    int32_t count,
    const ecs_entity_t *ids);

/* Set table to a fixed size. Useful for preallocating memory in advance. */
void ecs_table_set_size(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data,
    int32_t count);

/* Match table with filter */
bool ecs_table_match_filter(
    const ecs_world_t *world,
    const ecs_table_t *table,
    const ecs_filter_t *filter);

/* Get dirty state for table columns */
int32_t* ecs_table_get_dirty_state(
    ecs_table_t *table);

/* Get monitor for monitoring table changes */
int32_t* ecs_table_get_monitor(
    ecs_table_t *table);

/* Initialize root table */
void ecs_init_root_table(
    ecs_world_t *world);

/* Unset components in table */
void ecs_table_unset(
    ecs_world_t *world,
    ecs_table_t *table);

/* Free table */
void ecs_table_free(
    ecs_world_t *world,
    ecs_table_t *table); 

/* Merge table data */
void ecs_table_merge_data(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data);
    
/* Replace data */
void ecs_table_replace_data(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data);

/* Merge data of one table into another table */
ecs_data_t* ecs_table_merge(
    ecs_world_t *world,
    ecs_table_t *new_table,
    ecs_table_t *old_table,
    ecs_data_t *new_data,
    ecs_data_t *old_data);

void ecs_table_swap(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data,
    int32_t row_1,
    int32_t row_2);

ecs_table_t *ecs_table_traverse_add(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_entities_t *to_add,
    ecs_entities_t *added);

ecs_table_t *ecs_table_traverse_remove(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_entities_t *to_remove,
    ecs_entities_t *removed);

void ecs_table_mark_dirty(
    ecs_table_t *table,
    ecs_entity_t component);

const EcsComponent* ecs_component_from_id(
    const ecs_world_t *world,
    ecs_entity_t e);

int32_t ecs_table_switch_from_case(
    const ecs_world_t *world,
    const ecs_table_t *table,
    ecs_entity_t add);    

void ecs_table_notify(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_table_event_t *event);

void ecs_table_clear_edges(
    ecs_world_t *world,
    ecs_table_t *table);

void ecs_table_delete_entities(
    ecs_world_t *world,
    ecs_table_t *table);

////////////////////////////////////////////////////////////////////////////////
//// Query API
////////////////////////////////////////////////////////////////////////////////

void ecs_query_set_iter(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_iter_t *it,
    int32_t table_index,
    int32_t row,
    int32_t count);

void ecs_query_rematch(
    ecs_world_t *world,
    ecs_query_t *query);

void ecs_run_monitor(
    ecs_world_t *world,
    ecs_matched_query_t *monitor,
    ecs_entities_t *components,
    int32_t row,
    int32_t count,
    ecs_entity_t *entities);

bool ecs_query_match(
    const ecs_world_t *world,
    const ecs_table_t *table,
    const ecs_query_t *query,
    ecs_match_failure_t *failure_info);

void ecs_query_notify(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_query_event_t *event);


////////////////////////////////////////////////////////////////////////////////
//// Time API
////////////////////////////////////////////////////////////////////////////////

void ecs_os_time_setup(void);

uint64_t ecs_os_time_now(void);

void ecs_os_time_sleep(
    int32_t sec, 
    int32_t nanosec);

/* Increase or reset timer resolution (Windows only) */
FLECS_API
void ecs_increase_timer_resolution(
    bool enable);

////////////////////////////////////////////////////////////////////////////////
//// Utilities
////////////////////////////////////////////////////////////////////////////////

void ecs_hash(
    const void *data,
    ecs_size_t length,
    uint64_t *result);

/* Convert 64 bit signed integer to 16 bit */
int8_t ecs_to_i8(
    int64_t v);

/* Convert 64 bit signed integer to 16 bit */
int16_t ecs_to_i16(
    int64_t v);

/* Convert 64 bit unsigned integer to 32 bit */
uint32_t ecs_to_u32(
    uint64_t v);        

/* Convert signed integer to size_t */
size_t ecs_to_size_t(
    int64_t size);

/* Convert size_t to ecs_size_t */
ecs_size_t ecs_from_size_t(
    size_t size);    

/* Get next power of 2 */
int32_t ecs_next_pow_of_2(
    int32_t n);

/* Convert 64bit value to ecs_record_t type. ecs_record_t is stored as 64bit int in the
 * entity index */
ecs_record_t ecs_to_row(
    uint64_t value);

/* Get 64bit integer from ecs_record_t */
uint64_t ecs_from_row(
    ecs_record_t record);

/* Get actual row from record row */
int32_t ecs_record_to_row(
    int32_t row, 
    bool *is_watched_out);

/* Convert actual row to record row */
int32_t ecs_row_to_record(
    int32_t row, 
    bool is_watched);

/* Convert type to entity array */
ecs_entities_t ecs_type_to_entities(
    ecs_type_t type); 

/* Convert a symbol name to an entity name by removing the prefix */
const char* ecs_name_from_symbol(
    ecs_world_t *world,
    const char *type_name); 

/* Lookup an entity by name with a specific id */
ecs_entity_t ecs_lookup_w_id(
    ecs_world_t *world,
    ecs_entity_t e,
    const char *name);

/* Set entity name with symbol */
void ecs_set_symbol(
    ecs_world_t *world,
    ecs_entity_t e,
    const char *name);

/* Compare function for entity ids */
int ecs_entity_compare(
    ecs_entity_t e1, 
    const void *ptr1, 
    ecs_entity_t e2, 
    const void *ptr2); 

/* Compare function for entity ids which can be used with qsort */
int ecs_entity_compare_qsort(
    const void *e1,
    const void *e2);

#define assert_func(cond) _assert_func(cond, #cond, __FILE__, __LINE__, __func__)
void _assert_func(
    bool cond,
    const char *cond_str,
    const char *file,
    int32_t line,
    const char *func);

#endif

static
char *ecs_vasprintf(
    const char *fmt,
    va_list args)
{
    ecs_size_t size = 0;
    char *result  = NULL;
    va_list tmpa;

    va_copy(tmpa, args);

    size = vsnprintf(result, 0, fmt, tmpa);

    va_end(tmpa);

    if ((int32_t)size < 0) { 
        return NULL; 
    }

    result = (char *) ecs_os_malloc(size + 1);

    if (!result) { 
        return NULL; 
    }

    ecs_os_vsprintf(result, fmt, args);

    return result;
}

static
char* ecs_colorize(
    char *msg)
{
    ecs_strbuf_t buff = ECS_STRBUF_INIT;
    char *ptr, ch, prev = '\0';
    bool isNum = false;
    char isStr = '\0';
    bool isVar = false;
    bool overrideColor = false;
    bool autoColor = true;
    bool dontAppend = false;
    bool use_colors = true;

    for (ptr = msg; (ch = *ptr); ptr++) {
        dontAppend = false;

        if (!overrideColor) {
            if (isNum && !isdigit(ch) && !isalpha(ch) && (ch != '.') && (ch != '%')) {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_NORMAL);
                isNum = false;
            }
            if (isStr && (isStr == ch) && prev != '\\') {
                isStr = '\0';
            } else if (((ch == '\'') || (ch == '"')) && !isStr &&
                !isalpha(prev) && (prev != '\\'))
            {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_CYAN);
                isStr = ch;
            }

            if ((isdigit(ch) || (ch == '%' && isdigit(prev)) ||
                (ch == '-' && isdigit(ptr[1]))) && !isNum && !isStr && !isVar &&
                 !isalpha(prev) && !isdigit(prev) && (prev != '_') &&
                 (prev != '.'))
            {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_GREEN);
                isNum = true;
            }

            if (isVar && !isalpha(ch) && !isdigit(ch) && ch != '_') {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_NORMAL);
                isVar = false;
            }

            if (!isStr && !isVar && ch == '$' && isalpha(ptr[1])) {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_CYAN);
                isVar = true;
            }
        }

        if (!isVar && !isStr && !isNum && ch == '#' && ptr[1] == '[') {
            bool isColor = true;
            overrideColor = true;

            /* Custom colors */
            if (!ecs_os_strncmp(&ptr[2], "]", ecs_os_strlen("]"))) {
                autoColor = false;
            } else if (!ecs_os_strncmp(&ptr[2], "green]", ecs_os_strlen("green]"))) {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_GREEN);
            } else if (!ecs_os_strncmp(&ptr[2], "red]", ecs_os_strlen("red]"))) {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_RED);
            } else if (!ecs_os_strncmp(&ptr[2], "blue]", ecs_os_strlen("red]"))) {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_BLUE);
            } else if (!ecs_os_strncmp(&ptr[2], "magenta]", ecs_os_strlen("magenta]"))) {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_MAGENTA);
            } else if (!ecs_os_strncmp(&ptr[2], "cyan]", ecs_os_strlen("cyan]"))) {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_CYAN);
            } else if (!ecs_os_strncmp(&ptr[2], "yellow]", ecs_os_strlen("yellow]"))) {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_YELLOW);
            } else if (!ecs_os_strncmp(&ptr[2], "grey]", ecs_os_strlen("grey]"))) {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_GREY);
            } else if (!ecs_os_strncmp(&ptr[2], "white]", ecs_os_strlen("white]"))) {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_NORMAL);
            } else if (!ecs_os_strncmp(&ptr[2], "bold]", ecs_os_strlen("bold]"))) {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_BOLD);
            } else if (!ecs_os_strncmp(&ptr[2], "normal]", ecs_os_strlen("normal]"))) {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_NORMAL);
            } else if (!ecs_os_strncmp(&ptr[2], "reset]", ecs_os_strlen("reset]"))) {
                overrideColor = false;
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_NORMAL);
            } else {
                isColor = false;
                overrideColor = false;
            }

            if (isColor) {
                ptr += 2;
                while ((ch = *ptr) != ']') ptr ++;
                dontAppend = true;
            }
            if (!autoColor) {
                overrideColor = true;
            }
        }

        if (ch == '\n') {
            if (isNum || isStr || isVar || overrideColor) {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_NORMAL);
                overrideColor = false;
                isNum = false;
                isStr = false;
                isVar = false;
            }
        }

        if (!dontAppend) {
            ecs_strbuf_appendstrn(&buff, ptr, 1);
        }

        if (!overrideColor) {
            if (((ch == '\'') || (ch == '"')) && !isStr) {
                if (use_colors) ecs_strbuf_appendstr(&buff, ECS_NORMAL);
            }
        }

        prev = ch;
    }

    if (isNum || isStr || isVar || overrideColor) {
        if (use_colors) ecs_strbuf_appendstr(&buff, ECS_NORMAL);
    }

    return ecs_strbuf_get(&buff);
}

static int trace_indent = 0;
static int trace_level = 0;

static
void ecs_log_print(
    int level,
    const char *file,
    int32_t line,
    const char *fmt,
    va_list valist)
{
    (void)level;
    (void)line;

    if (level > trace_level) {
        return;
    }

    /* Massage filename so it doesn't take up too much space */
    char filebuff[256];
    ecs_os_strcpy(filebuff, file);
    file = filebuff;
    char *file_ptr = strrchr(file, '/');
    if (file_ptr) {
        file = file_ptr + 1;
    }

    /* Extension is likely the same for all files */
    file_ptr = strrchr(file, '.');
    if (file_ptr) {
        *file_ptr = '\0';
    }

    char indent[32];
    int i;
    for (i = 0; i < trace_indent; i ++) {
        indent[i * 2] = '|';
        indent[i * 2 + 1] = ' ';
    }
    indent[i * 2] = '\0';

    char *msg = ecs_vasprintf(fmt, valist);
    char *color_msg = ecs_colorize(msg);

    if (level >= 0) {
        ecs_os_log("%sinfo%s: %s%s%s%s",
            ECS_MAGENTA, ECS_NORMAL, ECS_GREY, indent, ECS_NORMAL, color_msg);
    } else if (level == -2) {
        ecs_os_warn("%swarn%s: %s%s%s%s",
            ECS_YELLOW, ECS_NORMAL, ECS_GREY, indent, ECS_NORMAL, color_msg);
    } else if (level <= -2) {
        ecs_os_err("%serr %s: %s%s%s%s",
            ECS_RED, ECS_NORMAL, ECS_GREY, indent, ECS_NORMAL, color_msg);
    }

    ecs_os_free(color_msg);
    ecs_os_free(msg);
}

void _ecs_trace(
    int level,
    const char *file,
    int32_t line,
    const char *fmt,
    ...)
{
    va_list valist;
    va_start(valist, fmt);

    ecs_log_print(level, file, line, fmt, valist);
}

void _ecs_warn(
    const char *file,
    int32_t line,
    const char *fmt,
    ...)
{
    va_list valist;
    va_start(valist, fmt);

    ecs_log_print(-2, file, line, fmt, valist);
}

void _ecs_err(
    const char *file,
    int32_t line,
    const char *fmt,
    ...)
{
    va_list valist;
    va_start(valist, fmt);

    ecs_log_print(-3, file, line, fmt, valist);
}

void ecs_log_push(void) {
    trace_indent ++;
}

void ecs_log_pop(void) {
    trace_indent --;
}

void ecs_tracing_enable(
    int level)
{
    trace_level = level;
}

void _ecs_parser_error(
    const char *name,
    const char *expr, 
    int64_t column,
    const char *fmt,
    ...)
{
    if (trace_level >= -2) {
        va_list valist;
        va_start(valist, fmt);
        char *msg = ecs_vasprintf(fmt, valist);

        if (column != -1) {
            if (name) {
                ecs_os_err("%s:%d: error: %s", name, column + 1, msg);
            } else {
                ecs_os_err("%d: error: %s", column + 1, msg);
            }
        } else {
            if (name) {
                ecs_os_err("%s: error: %s", name, msg);
            } else {
                ecs_os_err("error: %s", msg);
            }            
        }
        
        ecs_os_err("    %s", expr);

        if (column != -1) {
            ecs_os_err("    %*s^", column, "");
        } else {
            ecs_os_err("");
        }

        ecs_os_free(msg);        
    }

    ecs_os_abort();
}

void _ecs_abort(
    int32_t error_code,
    const char *param,
    const char *file,
    int32_t line)
{
    if (param) {
        ecs_err("abort %s:%d: %s (%s)",
            file, line, ecs_strerror(error_code), param);
    } else {
        ecs_err("abort %s:%d: %s", file, line, ecs_strerror(error_code));
    }

    ecs_os_abort();
}

void _ecs_assert(
    bool condition,
    int32_t error_code,
    const char *param,
    const char *condition_str,
    const char *file,
    int32_t line)
{
    if (!condition) {
        if (param) {
            ecs_err("assert(%s) %s:%d: %s (%s)",
                condition_str, file, line, ecs_strerror(error_code), param);
        } else {
            ecs_err("assert(%s) %s:%d: %s",
                condition_str, file, line, ecs_strerror(error_code));
        }

        ecs_os_abort();
    }
}

void _ecs_deprecated(
    const char *file,
    int32_t line,
    const char *msg)
{
    ecs_err("%s:%d: %s", file, line, msg);
}

const char* ecs_strerror(
    int32_t error_code)
{
    switch (error_code) {
    case ECS_INVALID_ENTITY:
        return "invalid entity";
    case ECS_INVALID_PARAMETER:
        return "invalid parameters";
    case ECS_INVALID_COMPONENT_ID:
        return "invalid component id";
    case ECS_INVALID_TYPE_EXPRESSION:
        return "invalid type expression";
    case ECS_INVALID_SIGNATURE:
        return "invalid system signature";
    case ECS_INVALID_EXPRESSION:
        return "invalid type expression/signature";
    case ECS_MISSING_SYSTEM_CONTEXT:
        return "missing system context";
    case ECS_UNKNOWN_COMPONENT_ID:
        return "unknown component id";
    case ECS_UNKNOWN_TYPE_ID:
        return "unknown type id";
    case ECS_TYPE_NOT_AN_ENTITY:
        return "type contains more than one entity";
    case ECS_NOT_A_COMPONENT:
        return "handle is not a component";
    case ECS_INTERNAL_ERROR:
        return "internal error";
    case ECS_MORE_THAN_ONE_PREFAB:
        return "more than one prefab added to entity";
    case ECS_ALREADY_DEFINED:
        return "entity has already been defined";
    case ECS_INVALID_COMPONENT_SIZE:
        return "the specified size does not match the component";
    case ECS_OUT_OF_MEMORY:
        return "out of memory";
    case ECS_MODULE_UNDEFINED:
        return "module is undefined";
    case ECS_COLUMN_INDEX_OUT_OF_RANGE:
        return "column index out of range";
    case ECS_COLUMN_IS_NOT_SHARED:
        return "column is not shared";
    case ECS_COLUMN_IS_SHARED:
        return "column is shared";
    case ECS_COLUMN_HAS_NO_DATA:
        return "column has no data";
    case ECS_COLUMN_TYPE_MISMATCH:
        return "column retrieved with mismatching type";
    case ECS_INVALID_WHILE_MERGING:
        return "operation is invalid while merging";
    case ECS_INVALID_WHILE_ITERATING:
        return "operation is invalid while iterating";    
    case ECS_INVALID_FROM_WORKER:
        return "operation is invalid from worker thread";
    case ECS_UNRESOLVED_IDENTIFIER:
        return "unresolved identifier";
    case ECS_OUT_OF_RANGE:
        return "index is out of range";
    case ECS_COLUMN_IS_NOT_SET:
        return "column is not set (use ecs_column_test for optional columns)";
    case ECS_UNRESOLVED_REFERENCE:
        return "unresolved reference for system";
    case ECS_THREAD_ERROR:
        return "failed to create thread";
    case ECS_MISSING_OS_API:
        return "missing implementation for OS API function";
    case ECS_TYPE_TOO_LARGE:
        return "type contains too many entities";
    case ECS_INVALID_PREFAB_CHILD_TYPE:
        return "a prefab child type must have at least one INSTANCEOF element";
    case ECS_UNSUPPORTED:
        return "operation is unsupported";
    case ECS_NO_OUT_COLUMNS:
        return "on demand system has no out columns";
    case ECS_COLUMN_ACCESS_VIOLATION:
        return "invalid access to readonly column (use const)";
    case ECS_DESERIALIZE_COMPONENT_ID_CONFLICT:
        return "serialized data contains conflicting component id";
    case ECS_DESERIALIZE_COMPONENT_SIZE_CONFLICT:
        return "serialized data contains conflicting component size";   
    case ECS_DESERIALIZE_FORMAT_ERROR:
        return "serialized data has invalid format";
    case ECS_INVALID_REACTIVE_SIGNATURE:
        return "signature is not valid for reactive system (must contain at least one ANY column)";
    case ECS_INCONSISTENT_COMPONENT_NAME:
        return "component redefined with a different name";
    case ECS_TYPE_CONSTRAINT_VIOLATION:
        return "type constraint violated";
    case ECS_COMPONENT_NOT_REGISTERED:
        return "component is not registered";
    case ECS_INCONSISTENT_COMPONENT_ID:
        return "component redefined with a different id";
    case ECS_INVALID_CASE:
        return "case not supported for type";
    case ECS_COMPONENT_NAME_IN_USE:
        return "component name is already in use";
    case ECS_INCONSISTENT_NAME:
        return "entity redefined with different name";
    case ECS_INCONSISTENT_COMPONENT_ACTION:
        return "registered mismatching component action";
    case ECS_INVALID_OPERATION:
        return "invalid operation";
    case ECS_INVALID_DELETE:
        return "invalid delete of entity/pair";
    case ECS_CYCLE_DETECTED:
        return "possible cycle detected";
    }

    return "unknown error code";
}

ecs_data_t* ecs_init_data(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *result)
{
    ecs_type_t type = table->type; 
    int32_t i, 
    count = table->column_count, 
    sw_count = table->sw_column_count,
    bs_count = table->bs_column_count;

    /* Root tables don't have columns */
    if (!count && !sw_count && !bs_count) {
        result->columns = NULL;
        return result;
    }

    ecs_entity_t *entities = ecs_vector_first(type, ecs_entity_t);

    if (count && !sw_count) {
        result->columns = ecs_os_calloc(ECS_SIZEOF(ecs_column_t) * count);    
    } else if (count || sw_count) {
        /* If a table has switch columns, store vector with the case values
            * as a regular column, so it's easier to access for systems. To
            * enable this, we need to allocate more space. */
        int32_t type_count = ecs_vector_count(type);
        result->columns = ecs_os_calloc(ECS_SIZEOF(ecs_column_t) * type_count);
    }

    if (count) {
        for (i = 0; i < count; i ++) {
            ecs_entity_t e = entities[i];

            /* Is the column a component? */
            const EcsComponent *component = ecs_component_from_id(world, e);
            if (component) {
                /* Is the component associated wit a (non-empty) type? */
                if (component->size) {
                    /* This is a regular component column */
                    result->columns[i].size = ecs_to_i16(component->size);
                    result->columns[i].alignment = ecs_to_i16(component->alignment);
                } else {
                    /* This is a tag */
                }
            } else {
                /* This is an entity that was added to the type */
            }
        }
    }

    if (sw_count) {
        int32_t sw_offset = table->sw_column_offset;
        result->sw_columns = ecs_os_calloc(ECS_SIZEOF(ecs_sw_column_t) * sw_count);

        for (i = 0; i < sw_count; i ++) {
            ecs_entity_t e = entities[i + sw_offset];
            ecs_assert(ECS_HAS_ROLE(e, SWITCH), ECS_INTERNAL_ERROR, NULL);
            e = e & ECS_COMPONENT_MASK;
            const EcsType *type_ptr = ecs_get(world, e, EcsType);
            ecs_assert(type_ptr != NULL, ECS_INTERNAL_ERROR, NULL);
            ecs_type_t sw_type = type_ptr->normalized;

            ecs_entity_t *sw_array = ecs_vector_first(sw_type, ecs_entity_t);
            int32_t sw_array_count = ecs_vector_count(sw_type);

            ecs_switch_t *sw = ecs_switch_new(
                sw_array[0], 
                sw_array[sw_array_count - 1], 
                0);
            result->sw_columns[i].data = sw;
            result->sw_columns[i].type = sw_type;

            int32_t column_id = i + table->sw_column_offset;
            result->columns[column_id].data = ecs_switch_values(sw);
            result->columns[column_id].size = sizeof(ecs_entity_t);
            result->columns[column_id].alignment = ECS_ALIGNOF(ecs_entity_t);
        }
    }
    
    if (bs_count) {
        result->bs_columns = ecs_os_calloc(ECS_SIZEOF(ecs_bs_column_t) * bs_count);
        for (i = 0; i < bs_count; i ++) {
            ecs_bitset_init(&result->bs_columns[i].data);
        }
    }

    return result;
}

static
ecs_flags32_t get_component_action_flags(
    const ecs_type_info_t *c_info) 
{
    ecs_flags32_t flags = 0;

    if (c_info->lifecycle.ctor) {
        flags |= EcsTableHasCtors;
    }
    if (c_info->lifecycle.dtor) {
        flags |= EcsTableHasDtors;
    }
    if (c_info->lifecycle.copy) {
        flags |= EcsTableHasCopy;
    }
    if (c_info->lifecycle.move) {
        flags |= EcsTableHasMove;
    }
    if (c_info->on_add) {
        flags |= EcsTableHasOnAdd;
    }
    if (c_info->on_remove) {
        flags |= EcsTableHasOnRemove;
    }    

    return flags;  
}

/* Check if table has instance of component, including pairs */
static
bool has_component(
    ecs_world_t *world,
    ecs_type_t type,
    ecs_entity_t component)
{
    ecs_entity_t *entities = ecs_vector_first(type, ecs_entity_t);
    int32_t i, count = ecs_vector_count(type);

    for (i = 0; i < count; i ++) {
        if (component == ecs_get_typeid(world, entities[i])) {
            return true;
        }
    }
    
    return false;
}

static
void notify_component_info(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_entity_t component)
{
    ecs_type_t table_type = table->type;
    if (!component || has_component(world, table_type, component)){
        int32_t column_count = ecs_vector_count(table_type);
        ecs_assert(!component || column_count != 0, ECS_INTERNAL_ERROR, NULL);

        if (!column_count) {
            return;
        }
        
        if (!table->c_info) {
            table->c_info = ecs_os_calloc(
                ECS_SIZEOF(ecs_type_info_t*) * column_count);
        }

        /* Reset lifecycle flags before recomputing */
        table->flags &= ~EcsTableHasLifecycle;

        /* Recompute lifecycle flags */
        ecs_entity_t *array = ecs_vector_first(table_type, ecs_entity_t);
        int32_t i;
        for (i = 0; i < column_count; i ++) {
            ecs_entity_t c = ecs_get_typeid(world, array[i]);
            if (!c) {
                continue;
            }
            
            const ecs_type_info_t *c_info = ecs_get_c_info(world, c);
            if (c_info) {
                ecs_flags32_t flags = get_component_action_flags(c_info);
                table->flags |= flags;
            }

            /* Store pointer to c_info for fast access */
            table->c_info[i] = (ecs_type_info_t*)c_info;
        }        
    }
}

static
void notify_trigger(
    ecs_world_t *world, 
    ecs_table_t *table, 
    ecs_entity_t event) 
{
    (void)world;

    if (!(table->flags & EcsTableIsDisabled)) {
        if (event == EcsOnAdd) {
            table->flags |= EcsTableHasOnAdd;
        } else if (event == EcsOnRemove) {
            table->flags |= EcsTableHasOnRemove;
        }
    }
}

static
void run_un_set_handlers(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data)
{
    int32_t count = ecs_vector_count(data->entities);
    if (count) {
        ecs_run_monitors(world, table, table->un_set_all, 0, count, NULL);
    }
}

static
int compare_matched_query(
    const void *ptr1,
    const void *ptr2)
{
    const ecs_matched_query_t *m1 = ptr1;
    const ecs_matched_query_t *m2 = ptr2;
    ecs_query_t *q1 = m1->query;
    ecs_query_t *q2 = m2->query;
    ecs_assert(q1 != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(q2 != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_entity_t s1 = q1->system;
    ecs_entity_t s2 = q2->system;
    ecs_assert(s1 != 0, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(s2 != 0, ECS_INTERNAL_ERROR, NULL);

    return (s1 > s2) - (s1 < s2);
}

static
void add_monitor(
    ecs_vector_t **array,
    ecs_query_t *query,
    int32_t matched_table_index)
{
    /* Add the system to a list that contains all OnSet systems matched with
     * this table. This makes it easy to get the list of systems that need to be
     * executed when all components are set, like when new_w_data is used */
    ecs_matched_query_t *m = ecs_vector_add(array, ecs_matched_query_t);
    ecs_assert(m != NULL, ECS_INTERNAL_ERROR, NULL);

    m->query = query;
    m->matched_table_index = matched_table_index;

    /* Sort the system list so that it is easy to get the difference OnSet
     * OnSet systems between two tables. */
    qsort(
        ecs_vector_first(*array, ecs_matched_query_t), 
        ecs_to_size_t(ecs_vector_count(*array)),
        ECS_SIZEOF(ecs_matched_query_t), 
        compare_matched_query);
}

/* This function is called when a query is matched with a table. A table keeps
 * a list of queries that match so that they can be notified when the table
 * becomes empty / non-empty. */
static
void register_monitor(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_query_t *query,
    int32_t matched_table_index)
{
    (void)world;
    ecs_assert(query != NULL, ECS_INTERNAL_ERROR, NULL);

    /* First check if system is already registered as monitor. It is possible
     * the query just wants to update the matched_table_index (for example, if
     * query tables got reordered) */
    ecs_vector_each(table->monitors, ecs_matched_query_t, m, {
        if (m->query == query) {
            m->matched_table_index = matched_table_index;
            return;
        }
    });

    add_monitor(&table->monitors, query, matched_table_index);

#ifndef NDEBUG
    char *str = ecs_type_str(world, table->type);
    ecs_trace_2("monitor #[green]%s#[reset] registered with table #[red]%s",
        ecs_get_name(world, query->system), str);
    ecs_os_free(str);
#endif
}

static
bool is_override(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_entity_t comp)
{
    if (!(table->flags & EcsTableHasBase)) {
        return false;
    }

    ecs_type_t type = table->type;
    int32_t i, count = ecs_vector_count(type);
    ecs_entity_t *entities = ecs_vector_first(type, ecs_entity_t);

    for (i = count - 1; i >= 0; i --) {
        ecs_entity_t e = entities[i];
        if (ECS_HAS_RELATION(e, EcsIsA)) {
            if (ecs_has_id(world, ECS_PAIR_OBJECT(e), comp)) {
                return true;
            }
        }
    }

    return false;
}

static
void register_on_set(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_query_t *query,
    int32_t matched_table_index)
{
    (void)world;

    if (table->column_count) {
        if (!table->on_set) {
            table->on_set = 
                ecs_os_calloc(ECS_SIZEOF(ecs_vector_t) * table->column_count);
        }

        /* Get the matched table which holds the list of actual components */
        ecs_matched_table_t *matched_table = ecs_vector_get(
            query->tables, ecs_matched_table_t, matched_table_index);

        /* Keep track of whether query matches overrides. When a component is
         * removed, diffing these arrays between the source and detination
         * tables gives the list of OnSet systems to run, after exposing the
         * component that was overridden. */
        bool match_override = false;

        /* Add system to each matched column. This makes it easy to get the list 
         * of systems when setting a single component. */
        ecs_term_t *terms = query->filter.terms;
        int32_t i, count = query->filter.term_count;
        
        for (i = 0; i < count; i ++) {
            ecs_term_t *term = &terms[i];
            ecs_term_id_t *subj = &term->args[0];
            ecs_oper_kind_t oper = term->oper;

            if (!(subj->set & EcsSelf) || !subj->entity ||
                subj->entity != EcsThis)
            {
                continue;
            }

            if (oper != EcsAnd && oper != EcsOptional) {
                continue;
            }

            ecs_entity_t comp = matched_table->iter_data.components[i];
            int32_t index = ecs_type_index_of(table->type, comp);
            if (index == -1) {
                continue;
            }

            if (index >= table->column_count) {
                continue;
            }
            
            ecs_vector_t *set_c = table->on_set[index];
            ecs_matched_query_t *m = ecs_vector_add(&set_c, ecs_matched_query_t);
            m->query = query;
            m->matched_table_index = matched_table_index;
            table->on_set[index] = set_c;
            
            match_override |= is_override(world, table, comp);
        } 

        if (match_override) {
            add_monitor(&table->on_set_override, query, matched_table_index);
        }
    }

    add_monitor(&table->on_set_all, query, matched_table_index);   
}

static
void register_un_set(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_query_t *query,
    int32_t matched_table_index)
{
    (void)world;
    table->flags |= EcsTableHasUnSet;
    add_monitor(&table->un_set_all, query, matched_table_index);
}

/* -- Private functions -- */

/* If table goes from 0 to >0 entities or from >0 entities to 0 entities notify
 * queries. This allows systems associated with queries to move inactive tables
 * out of the main loop. */
void ecs_table_activate(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_query_t *query,
    bool activate)
{
    if (query) {
        ecs_query_notify(world, query, &(ecs_query_event_t) {
            .kind = activate ? EcsQueryTableNonEmpty : EcsQueryTableEmpty,
            .table = table
        });
    } else {
        ecs_vector_t *queries = table->queries;
        ecs_query_t **buffer = ecs_vector_first(queries, ecs_query_t*);
        int32_t i, count = ecs_vector_count(queries);

        for (i = 0; i < count; i ++) {
            ecs_query_notify(world, buffer[i], &(ecs_query_event_t) {
                .kind = activate ? EcsQueryTableNonEmpty : EcsQueryTableEmpty,
                .table = table
            });                
        }
    }     
}

/* This function is called when a query is matched with a table. A table keeps
 * a list of tables that match so that they can be notified when the table
 * becomes empty / non-empty. */
static
void register_query(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_query_t *query,
    int32_t matched_table_index)
{
    /* Register system with the table */
    if (!(query->flags & EcsQueryNoActivation)) {
#ifndef NDEBUG
        /* Sanity check if query has already been added */
        int32_t i, count = ecs_vector_count(table->queries);
        for (i = 0; i < count; i ++) {
            ecs_query_t **q = ecs_vector_get(table->queries, ecs_query_t*, i);
            ecs_assert(*q != query, ECS_INTERNAL_ERROR, NULL);
        }
#endif

        ecs_query_t **q = ecs_vector_add(&table->queries, ecs_query_t*);
        if (q) *q = query;

        ecs_data_t *data = ecs_table_get_data(table);
        if (data && ecs_vector_count(data->entities)) {
            ecs_table_activate(world, table, query, true);
        }
    }

    /* Register the query as a monitor */
    if (query->flags & EcsQueryMonitor) {
        table->flags |= EcsTableHasMonitors;
        register_monitor(world, table, query, matched_table_index);
    }

    /* Register the query as an on_set system */
    if (query->flags & EcsQueryOnSet) {
        register_on_set(world, table, query, matched_table_index);
    }

    /* Register the query as an un_set system */
    if (query->flags & EcsQueryUnSet) {
        register_un_set(world, table, query, matched_table_index);
    }
}

/* This function is called when a query is unmatched with a table. This can
 * happen for queries that have shared components expressions in their signature
 * and those shared components changed (for example, a base removed a comp). */
static
void unregister_query(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_query_t *query)
{
    (void)world;

    if (!(query->flags & EcsQueryNoActivation)) {
        int32_t i, count = ecs_vector_count(table->queries);
        for (i = 0; i < count; i ++) {
            ecs_query_t **q = ecs_vector_get(table->queries, ecs_query_t*, i);
            if (*q == query) {
                break;
            }
        }

        /* Query must have been registered with table */
        ecs_assert(i != count, ECS_INTERNAL_ERROR, NULL);

        /* Remove query */
        ecs_vector_remove_index(table->queries, ecs_query_t*, i);        
    }
}

ecs_data_t* ecs_table_get_data(
    const ecs_table_t *table)
{
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);

    return table->data;
}

ecs_data_t* ecs_table_get_or_create_data(
    ecs_table_t *table)
{
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_data_t *data = table->data;
    if (!data) {
        data = table->data = ecs_os_calloc(ECS_SIZEOF(ecs_data_t));
    }
    return data;
}

static
void ctor_component(
    ecs_world_t *world,
    ecs_type_info_t * cdata,
    ecs_column_t * column,
    ecs_entity_t * entities,
    int32_t row,
    int32_t count)
{
    /* A new component is constructed */
    ecs_xtor_t ctor;
    if (cdata && (ctor = cdata->lifecycle.ctor)) {
        void *ctx = cdata->lifecycle.ctx;
        int16_t size = column->size;
        int16_t alignment = column->alignment;

        void *ptr = ecs_vector_get_t(column->data, size, alignment, row);

        ctor(world, cdata->component, entities, ptr, 
            ecs_to_size_t(size), count, ctx);
    }
}

static
void dtor_component(
    ecs_world_t *world,
    ecs_type_info_t * cdata,
    ecs_column_t * column,
    ecs_entity_t * entities,
    int32_t row,
    int32_t count)
{
    if (!count) {
        return;
    }
    
    /* An old component is destructed */
    ecs_xtor_t dtor;
    if (cdata && (dtor = cdata->lifecycle.dtor)) {
        void *ctx = cdata->lifecycle.ctx;
        int16_t size = column->size;
        int16_t alignment = column->alignment;    

        void *ptr = ecs_vector_get_t(column->data, size, alignment, row);
        ecs_assert(ptr != NULL, ECS_INTERNAL_ERROR, NULL);

        dtor(world, cdata->component, entities, ptr,
            ecs_to_size_t(size), count, ctx);
    }
}

static
void dtor_all_components(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t * data,
    int32_t row,
    int32_t count)
{
    ecs_entity_t *entities = ecs_vector_first(data->entities, ecs_entity_t);
    int32_t column_count = table->column_count;
    int32_t i;
    for (i = 0; i < column_count; i ++) {
        ecs_column_t *column = &data->columns[i];
        dtor_component(
            world, table->c_info[i], column, entities, row, 
            count);
    }
}

static
void run_remove_actions(
    ecs_world_t *world,
    ecs_table_t *table,
    int32_t row,
    int32_t count)
{
    if (count) {
        ecs_run_monitors(world, table, NULL, row, count, table->un_set_all);        
    }
}

void ecs_table_clear_data(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data)
{
    if (!data) {
        return;
    }

    int32_t count = ecs_table_data_count(data);
    dtor_all_components(world, table, data, 0, count);
    
    ecs_column_t *columns = data->columns;
    if (columns) {
        int32_t c, column_count = table->column_count;
        for (c = 0; c < column_count; c ++) {
            ecs_vector_free(columns[c].data);
        }
        ecs_os_free(columns);
        data->columns = NULL;
    }

    ecs_sw_column_t *sw_columns = data->sw_columns;
    if (sw_columns) {
        int32_t c, column_count = table->sw_column_count;
        for (c = 0; c < column_count; c ++) {
            ecs_switch_free(sw_columns[c].data);
        }
        ecs_os_free(sw_columns);
        data->sw_columns = NULL;
    }

    ecs_bs_column_t *bs_columns = data->bs_columns;
    if (bs_columns) {
        int32_t c, column_count = table->bs_column_count;
        for (c = 0; c < column_count; c ++) {
            ecs_bitset_deinit(&bs_columns[c].data);
        }
        ecs_os_free(bs_columns);
        data->bs_columns = NULL;
    }    

    ecs_vector_free(data->entities);
    ecs_vector_free(data->record_ptrs);

    data->entities = NULL;
    data->record_ptrs = NULL;
}

/* Clear columns. Deactivate table in systems if necessary, but do not invoke
 * OnRemove handlers. This is typically used when restoring a table to a
 * previous state. */
void ecs_table_clear_silent(
    ecs_world_t *world,
    ecs_table_t *table)
{
    ecs_data_t *data = ecs_table_get_data(table);
    if (!data) {
        return;
    }

    int32_t count = ecs_vector_count(data->entities);
    
    ecs_table_clear_data(world, table, data);

    if (count) {
        ecs_table_activate(world, table, 0, false);
    }
}

void ecs_table_delete_entities(
    ecs_world_t *world,
    ecs_table_t *table)
{
    ecs_data_t *data = ecs_table_get_data(table);

    if (data) {
        run_remove_actions(world, table, 0, ecs_table_data_count(data));

        ecs_entity_t *entities = ecs_vector_first(data->entities, ecs_entity_t);
        int32_t i, count = ecs_vector_count(data->entities);
        for(i = 0; i < count; i ++) {
            ecs_eis_delete(world, entities[i]);
        }        

        ecs_table_clear_silent(world, table);
    }
}

/* Delete all entities in table, invoke OnRemove handlers. This function is used
 * when an application invokes delete_w_filter. Use ecs_table_clear_silent, as 
 * the table may have to be deactivated with systems. */
void ecs_table_clear(
    ecs_world_t *world,
    ecs_table_t *table)
{
    ecs_data_t *data = ecs_table_get_data(table);

    if (data) {
        run_remove_actions(world, table, 0, ecs_table_data_count(data));

        ecs_entity_t *entities = ecs_vector_first(data->entities, ecs_entity_t);
        int32_t i, count = ecs_vector_count(data->entities);
        for(i = 0; i < count; i ++) {
            ecs_record_t r = {NULL, 0};
            ecs_eis_set(world, entities[i], &r);
        } 

        ecs_table_clear_silent(world, table);
    }
}

/* Unset all components in table. This function is called before a table is 
 * deleted, and invokes all UnSet handlers, if any */
void ecs_table_unset(
    ecs_world_t *world,
    ecs_table_t *table)
{
    (void)world;
    ecs_data_t *data = ecs_table_get_data(table);
    if (data) {
        run_un_set_handlers(world, table, data);
    }   
}

/* Free table resources. */
void ecs_table_free(
    ecs_world_t *world,
    ecs_table_t *table)
{
    (void)world;
    ecs_data_t *data = ecs_table_get_data(table);
    if (data) {
        run_remove_actions(world, table, 0, ecs_table_data_count(data));
        ecs_table_clear_data(world, table, data);
    }

    ecs_table_clear_edges(world, table);

    ecs_unregister_table(world, table);

    ecs_os_free(table->lo_edges);
    ecs_map_free(table->hi_edges);
    ecs_vector_free(table->queries);
    ecs_vector_free((ecs_vector_t*)table->type);
    ecs_os_free(table->dirty_state);
    ecs_vector_free(table->monitors);
    ecs_vector_free(table->on_set_all);
    ecs_vector_free(table->on_set_override);
    ecs_vector_free(table->un_set_all);

    if (table->c_info) {
        ecs_os_free(table->c_info);
    }
    
    if (table->on_set) {
        int32_t i;
        for (i = 0; i < table->column_count; i ++) {
            ecs_vector_free(table->on_set[i]);
        }
        ecs_os_free(table->on_set);
    }

    table->id = 0;

    ecs_os_free(table->data);
}

/* Reset a table to its initial state. */
void ecs_table_reset(
    ecs_world_t *world,
    ecs_table_t *table)
{
    (void)world;
    ecs_os_free(table->lo_edges);
    ecs_map_free(table->hi_edges);
    table->lo_edges = NULL;
    table->hi_edges = NULL;
}

static
void mark_table_dirty(
    ecs_table_t *table,
    int32_t index)
{
    if (table->dirty_state) {
        table->dirty_state[index] ++;
    }
}

void ecs_table_mark_dirty(
    ecs_table_t *table,
    ecs_entity_t component)
{
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);
    if (table->dirty_state) {
        int32_t index = ecs_type_index_of(table->type, component);
        ecs_assert(index != -1, ECS_INTERNAL_ERROR, NULL);
        table->dirty_state[index] ++;
    }
}

static
void move_switch_columns(
    ecs_table_t * new_table, 
    ecs_data_t * new_data, 
    int32_t new_index,
    ecs_table_t * old_table, 
    ecs_data_t * old_data, 
    int32_t old_index,
    int32_t count)
{
    int32_t i_old = 0, old_column_count = old_table->sw_column_count;
    int32_t i_new = 0, new_column_count = new_table->sw_column_count;

    if (!old_column_count || !new_column_count) {
        return;
    }

    ecs_sw_column_t *old_columns = old_data->sw_columns;
    ecs_sw_column_t *new_columns = new_data->sw_columns;

    ecs_type_t new_type = new_table->type;
    ecs_type_t old_type = old_table->type;

    int32_t offset_new = new_table->sw_column_offset;
    int32_t offset_old = old_table->sw_column_offset;

    ecs_entity_t *new_components = ecs_vector_first(new_type, ecs_entity_t);
    ecs_entity_t *old_components = ecs_vector_first(old_type, ecs_entity_t);

    for (; (i_new < new_column_count) && (i_old < old_column_count);) {
        ecs_entity_t new_component = new_components[i_new + offset_new];
        ecs_entity_t old_component = old_components[i_old + offset_old];

        if (new_component == old_component) {
            ecs_switch_t *old_switch = old_columns[i_old].data;
            ecs_switch_t *new_switch = new_columns[i_new].data;

            ecs_switch_ensure(new_switch, new_index + count);

            int i;
            for (i = 0; i < count; i ++) {
                uint64_t value = ecs_switch_get(old_switch, old_index + i);
                ecs_switch_set(new_switch, new_index + i, value);
            }
        }

        i_new += new_component <= old_component;
        i_old += new_component >= old_component;
    }
}

static
void move_bitset_columns(
    ecs_table_t * new_table, 
    ecs_data_t * new_data, 
    int32_t new_index,
    ecs_table_t * old_table, 
    ecs_data_t * old_data, 
    int32_t old_index,
    int32_t count)
{
    int32_t i_old = 0, old_column_count = old_table->bs_column_count;
    int32_t i_new = 0, new_column_count = new_table->bs_column_count;

    if (!old_column_count || !new_column_count) {
        return;
    }

    ecs_bs_column_t *old_columns = old_data->bs_columns;
    ecs_bs_column_t *new_columns = new_data->bs_columns;

    ecs_type_t new_type = new_table->type;
    ecs_type_t old_type = old_table->type;

    int32_t offset_new = new_table->bs_column_offset;
    int32_t offset_old = old_table->bs_column_offset;

    ecs_entity_t *new_components = ecs_vector_first(new_type, ecs_entity_t);
    ecs_entity_t *old_components = ecs_vector_first(old_type, ecs_entity_t);

    for (; (i_new < new_column_count) && (i_old < old_column_count);) {
        ecs_entity_t new_component = new_components[i_new + offset_new];
        ecs_entity_t old_component = old_components[i_old + offset_old];

        if (new_component == old_component) {
            ecs_bitset_t *old_bs = &old_columns[i_old].data;
            ecs_bitset_t *new_bs = &new_columns[i_new].data;

            ecs_bitset_ensure(new_bs, new_index + count);

            int i;
            for (i = 0; i < count; i ++) {
                uint64_t value = ecs_bitset_get(old_bs, old_index + i);
                ecs_bitset_set(new_bs, new_index + i, value);
            }
        }

        i_new += new_component <= old_component;
        i_old += new_component >= old_component;
    }
}

static
void ensure_data(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t * data,
    int32_t * column_count_out,
    int32_t * sw_column_count_out,
    int32_t * bs_column_count_out,
    ecs_column_t ** columns_out,
    ecs_sw_column_t ** sw_columns_out,
    ecs_bs_column_t ** bs_columns_out)
{
    int32_t column_count = table->column_count;
    int32_t sw_column_count = table->sw_column_count;
    int32_t bs_column_count = table->bs_column_count;
    ecs_column_t *columns = NULL;
    ecs_sw_column_t *sw_columns = NULL;
    ecs_bs_column_t *bs_columns = NULL;

    /* It is possible that the table data was created without content. 
     * Now that data is going to be written to the table, initialize */ 
    if (column_count | sw_column_count | bs_column_count) {
        columns = data->columns;
        sw_columns = data->sw_columns;
        bs_columns = data->bs_columns;

        if (!columns && !sw_columns && !bs_columns) {
            ecs_init_data(world, table, data);
            columns = data->columns;
            sw_columns = data->sw_columns;
            bs_columns = data->bs_columns;

            ecs_assert(sw_column_count == 0 || sw_columns != NULL, 
                ECS_INTERNAL_ERROR, NULL);
            ecs_assert(bs_column_count == 0 || bs_columns != NULL, 
                ECS_INTERNAL_ERROR, NULL);
        }

        *column_count_out = column_count;
        *sw_column_count_out = sw_column_count;
        *bs_column_count_out = bs_column_count;
        *columns_out = columns;
        *sw_columns_out = sw_columns;
        *bs_columns_out = bs_columns;
    }
}

static
void grow_column(
    ecs_world_t *world,
    ecs_entity_t * entities,
    ecs_column_t * column,
    ecs_type_info_t * c_info,
    int32_t to_add,
    int32_t new_size,
    bool construct)
{
    ecs_vector_t *vec = column->data;
    int16_t alignment = column->alignment;

    int32_t size = column->size;
    int32_t count = ecs_vector_count(vec);
    int32_t old_size = ecs_vector_size(vec);
    int32_t new_count = count + to_add;
    bool can_realloc = new_size != old_size;

    ecs_assert(new_size >= new_count, ECS_INTERNAL_ERROR, NULL);

    /* If the array could possibly realloc and the component has a move action 
     * defined, move old elements manually */
    ecs_move_t move;
    if (c_info && count && can_realloc && (move = c_info->lifecycle.move)) {
        ecs_xtor_t ctor = c_info->lifecycle.ctor;
        ecs_assert(ctor != NULL, ECS_INTERNAL_ERROR, NULL);

        /* Create new vector */
        ecs_vector_t *new_vec = ecs_vector_new_t(size, alignment, new_size);
        ecs_vector_set_count_t(&new_vec, size, alignment, new_count);

        void *old_buffer = ecs_vector_first_t(
            vec, size, alignment);

        void *new_buffer = ecs_vector_first_t(
            new_vec, size, alignment);

        /* First construct elements (old and new) in new buffer */
        ctor(world, c_info->component, entities, new_buffer, 
            ecs_to_size_t(size), construct ? new_count : count, 
            c_info->lifecycle.ctx);
        
        /* Move old elements */
        move(world, c_info->component, entities, entities, 
            new_buffer, old_buffer, ecs_to_size_t(size), count, 
            c_info->lifecycle.ctx);

        /* Free old vector */
        ecs_vector_free(vec);
        column->data = new_vec;
    } else {
        /* If array won't realloc or has no move, simply add new elements */
        if (can_realloc) {
            ecs_vector_set_size_t(&vec, size, alignment, new_size);
        }

        void *elem = ecs_vector_addn_t(&vec, size, alignment, to_add);

        ecs_xtor_t ctor;
        if (construct && c_info && (ctor = c_info->lifecycle.ctor)) {
            /* If new elements need to be constructed and component has a
             * constructor, construct */
            ctor(world, c_info->component, &entities[count], elem, 
                ecs_to_size_t(size), to_add, c_info->lifecycle.ctx);
        }

        column->data = vec;
    }

    ecs_assert(ecs_vector_size(column->data) == new_size, 
        ECS_INTERNAL_ERROR, NULL);
}

static
int32_t grow_data(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t * data,
    int32_t to_add,
    int32_t size,
    const ecs_entity_t *ids)
{
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(data != NULL, ECS_INTERNAL_ERROR, NULL);

    int32_t cur_count = ecs_table_data_count(data);
    int32_t column_count = table->column_count;
    int32_t sw_column_count = table->sw_column_count;
    int32_t bs_column_count = table->bs_column_count;
    ecs_column_t *columns = NULL;
    ecs_sw_column_t *sw_columns = NULL;
    ecs_bs_column_t *bs_columns = NULL;
    ensure_data(world, table, data, &column_count, &sw_column_count, 
        &bs_column_count, &columns, &sw_columns, &bs_columns);    

    /* Add record to record ptr array */
    ecs_vector_set_size(&data->record_ptrs, ecs_record_t*, size);
    ecs_record_t **r = ecs_vector_addn(&data->record_ptrs, ecs_record_t*, to_add);
    ecs_assert(r != NULL, ECS_INTERNAL_ERROR, NULL);
    if (ecs_vector_size(data->record_ptrs) > size) {
        size = ecs_vector_size(data->record_ptrs);
    }

    /* Add entity to column with entity ids */
    ecs_vector_set_size(&data->entities, ecs_entity_t, size);
    ecs_entity_t *e = ecs_vector_addn(&data->entities, ecs_entity_t, to_add);
    ecs_assert(e != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(ecs_vector_size(data->entities) == size, ECS_INTERNAL_ERROR, NULL);

    /* Initialize entity ids and record ptrs */
    int32_t i;
    if (ids) {
        for (i = 0; i < to_add; i ++) {
            e[i] = ids[i];
        }
    } else {
        ecs_os_memset(e, 0, ECS_SIZEOF(ecs_entity_t) * to_add);
    }
    ecs_os_memset(r, 0, ECS_SIZEOF(ecs_record_t*) * to_add);

    /* Add elements to each column array */
    ecs_type_info_t **c_info_array = table->c_info;
    ecs_entity_t *entities = ecs_vector_first(data->entities, ecs_entity_t);
    for (i = 0; i < column_count; i ++) {
        ecs_column_t *column = &columns[i];
        if (!column->size) {
            continue;
        }

        ecs_type_info_t *c_info = NULL;
        if (c_info_array) {
            c_info = c_info_array[i];
        }

        grow_column(world, entities, column, c_info, to_add, size, true);
        ecs_assert(ecs_vector_size(columns[i].data) == size, 
            ECS_INTERNAL_ERROR, NULL);
    }

    /* Add elements to each switch column */
    for (i = 0; i < sw_column_count; i ++) {
        ecs_switch_t *sw = sw_columns[i].data;
        ecs_switch_addn(sw, to_add);
    }

    /* Add elements to each bitset column */
    for (i = 0; i < bs_column_count; i ++) {
        ecs_bitset_t *bs = &bs_columns[i].data;
        ecs_bitset_addn(bs, to_add);
    }

    /* If the table is monitored indicate that there has been a change */
    mark_table_dirty(table, 0);

    if (!world->is_readonly && !cur_count) {
        ecs_table_activate(world, table, 0, true);
    }

    table->alloc_count ++;

    /* Return index of first added entity */
    return cur_count;
}

static
void fast_append(
    ecs_column_t *columns,
    int32_t column_count)
{
    /* Add elements to each column array */
    int32_t i;
    for (i = 0; i < column_count; i ++) {
        ecs_column_t *column = &columns[i];
        int16_t size = column->size;
        if (size) {
            int16_t alignment = column->alignment;
            ecs_vector_add_t(&column->data, size, alignment);
        }
    }
}

int32_t ecs_table_append(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t * data,
    ecs_entity_t entity,
    ecs_record_t * record,
    bool construct)
{
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(data != NULL, ECS_INTERNAL_ERROR, NULL);

    /* Get count & size before growing entities array. This tells us whether the
     * arrays will realloc */
    int32_t count = ecs_vector_count(data->entities);
    int32_t size = ecs_vector_size(data->entities);

    int32_t column_count = table->column_count;
    int32_t sw_column_count = table->sw_column_count;
    int32_t bs_column_count = table->bs_column_count;
    ecs_column_t *columns = NULL;
    ecs_sw_column_t *sw_columns = NULL;
    ecs_bs_column_t *bs_columns = NULL;

    ensure_data(world, table, data, &column_count, &sw_column_count,
        &bs_column_count, &columns, &sw_columns, &bs_columns);

    /* Grow buffer with entity ids, set new element to new entity */
    ecs_entity_t *e = ecs_vector_add(&data->entities, ecs_entity_t);
    ecs_assert(e != NULL, ECS_INTERNAL_ERROR, NULL);
    *e = entity;    

    /* Keep track of alloc count. This allows references to check if cached
     * pointers need to be updated. */  
    table->alloc_count += (count == size);

    /* Add record ptr to array with record ptrs */
    ecs_record_t **r = ecs_vector_add(&data->record_ptrs, ecs_record_t*);
    ecs_assert(r != NULL, ECS_INTERNAL_ERROR, NULL);
    *r = record;
 
    /* If the table is monitored indicate that there has been a change */
    mark_table_dirty(table, 0);

    /* If this is the first entity in this table, signal queries so that the
     * table moves from an inactive table to an active table. */
    if (!world->is_readonly && !count) {
        ecs_table_activate(world, table, 0, true);
    } 

    ecs_assert(count >= 0, ECS_INTERNAL_ERROR, NULL);

    /* Fast path: no switch columns, no lifecycle actions */
    if (!(table->flags & EcsTableIsComplex)) {
        fast_append(columns, column_count);
        return count;
    }

    ecs_type_info_t **c_info_array = table->c_info;
    ecs_entity_t *entities = ecs_vector_first(
        data->entities, ecs_entity_t);

    /* Reobtain size to ensure that the columns have the same size as the 
     * entities and record vectors. This keeps reasoning about when allocations
     * occur easier. */
    size = ecs_vector_size(data->entities);

    /* Grow component arrays with 1 element */
    int32_t i;
    for (i = 0; i < column_count; i ++) {
        ecs_column_t *column = &columns[i];
        if (!column->size) {
            continue;
        }

        ecs_type_info_t *c_info = NULL;
        if (c_info_array) {
            c_info = c_info_array[i];
        }

        grow_column(world, entities, column, c_info, 1, size, construct);
        
        ecs_assert(
            ecs_vector_size(columns[i].data) == ecs_vector_size(data->entities), 
            ECS_INTERNAL_ERROR, NULL); 
            
        ecs_assert(
            ecs_vector_count(columns[i].data) == ecs_vector_count(data->entities), 
            ECS_INTERNAL_ERROR, NULL);                        
    }

    /* Add element to each switch column */
    for (i = 0; i < sw_column_count; i ++) {
        ecs_assert(sw_columns != NULL, ECS_INTERNAL_ERROR, NULL);
        ecs_switch_t *sw = sw_columns[i].data;
        ecs_switch_add(sw);
        columns[i + table->sw_column_offset].data = ecs_switch_values(sw);
    }

    /* Add element to each bitset column */
    for (i = 0; i < bs_column_count; i ++) {
        ecs_assert(bs_columns != NULL, ECS_INTERNAL_ERROR, NULL);
        ecs_bitset_t *bs = &bs_columns[i].data;
        ecs_bitset_addn(bs, 1);
    }    

    return count;
}

static
void fast_delete_last(
    ecs_column_t *columns,
    int32_t column_count) 
{
    int i;
    for (i = 0; i < column_count; i ++) {
        ecs_column_t *column = &columns[i];
        ecs_vector_remove_last(column->data);
    }
}

static
void fast_delete(
    ecs_column_t *columns,
    int32_t column_count,
    int32_t index) 
{
    int i;
    for (i = 0; i < column_count; i ++) {
        ecs_column_t *column = &columns[i];
        int16_t size = column->size;
        if (size) {
            int16_t alignment = column->alignment;
            ecs_vector_remove_index_t(column->data, size, alignment, index);
        } 
    }
}

void ecs_table_delete(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t * data,
    int32_t index,
    bool destruct)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(data != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_vector_t *entity_column = data->entities;
    int32_t count = ecs_vector_count(entity_column);

    ecs_assert(count > 0, ECS_INTERNAL_ERROR, NULL);
    count --;
    
    ecs_assert(index <= count, ECS_INTERNAL_ERROR, NULL);

    ecs_type_info_t **c_info_array = table->c_info;
    int32_t column_count = table->column_count;
    int32_t i;

    ecs_entity_t *entities = ecs_vector_first(entity_column, ecs_entity_t);
    ecs_entity_t entity_to_move = entities[count];

    /* Move last entity id to index */
    entities[index] = entity_to_move;
    ecs_vector_remove_last(entity_column);

    /* Move last record ptr to index */
    ecs_vector_t *record_column = data->record_ptrs;     
    ecs_record_t **records = ecs_vector_first(record_column, ecs_record_t*);

    ecs_assert(count < ecs_vector_count(record_column), ECS_INTERNAL_ERROR, NULL);
    ecs_record_t *record_to_move = records[count];

    records[index] = record_to_move;
    ecs_vector_remove_last(record_column);    

    /* Update record of moved entity in entity index */
    if (index != count) {
        if (record_to_move) {
            if (record_to_move->row >= 0) {
                record_to_move->row = index + 1;
            } else {
                record_to_move->row = -(index + 1);
            }
            ecs_assert(record_to_move->table != NULL, ECS_INTERNAL_ERROR, NULL);
            ecs_assert(record_to_move->table == table, ECS_INTERNAL_ERROR, NULL);
        }
    } 

    /* If the table is monitored indicate that there has been a change */
    mark_table_dirty(table, 0);    

    if (!count) {
        ecs_table_activate(world, table, NULL, false);
    }

    /* Move each component value in array to index */
    ecs_column_t *columns = data->columns;

    if (!(table->flags & EcsTableIsComplex)) {
        if (index == count) {
            fast_delete_last(columns, column_count);
        } else {
            fast_delete(columns, column_count, index);
        }
        return;
    }

    for (i = 0; i < column_count; i ++) {
        ecs_column_t *column = &columns[i];
        int16_t size = column->size;
        int16_t alignment = column->alignment;
        if (size) {
            ecs_type_info_t *c_info = c_info_array ? c_info_array[i] : NULL;
            ecs_xtor_t dtor;

            void *dst = ecs_vector_get_t(column->data, size, alignment, index);

            ecs_move_t move;
            if (c_info && (count != index) && (move = c_info->lifecycle.move)) {
                void *ctx = c_info->lifecycle.ctx;
                void *src = ecs_vector_get_t(column->data, size, alignment, count);
                ecs_entity_t component = c_info->component;

                /* If the delete is not destructing the component, the component
                * was already deleted, most likely by a move. In that case we
                * still need to move, but we need to make sure we're moving
                * into an element that is initialized with valid memory, so
                * call the constructor. */
                if (!destruct) {
                    ecs_xtor_t ctor = c_info->lifecycle.ctor;
                    ecs_assert(ctor != NULL, ECS_INTERNAL_ERROR, NULL);
                    ctor(world, c_info->component, &entity_to_move, dst,
                        ecs_to_size_t(size), 1, c_info->lifecycle.ctx);   
                }

                /* Move last element into deleted element */
                move(world, component, &entity_to_move, &entity_to_move, dst, src,
                    ecs_to_size_t(size), 1, ctx);

                /* Memory has been copied, we can now simply remove last */
                ecs_vector_remove_last(column->data);                              
            } else {
                if (destruct && c_info && (dtor = c_info->lifecycle.dtor)) {
                    dtor(world, c_info->component, &entities[index], dst, 
                        ecs_to_size_t(size), 1, c_info->lifecycle.ctx);
                }

                ecs_vector_remove_index_t(column->data, size, alignment, index);
            }
        }
    }

    /* Remove elements from switch columns */
    ecs_sw_column_t *sw_columns = data->sw_columns;
    int32_t sw_column_count = table->sw_column_count;
    for (i = 0; i < sw_column_count; i ++) {
        ecs_switch_remove(sw_columns[i].data, index);
    }

    /* Remove elements from bitset columns */
    ecs_bs_column_t *bs_columns = data->bs_columns;
    int32_t bs_column_count = table->bs_column_count;
    for (i = 0; i < bs_column_count; i ++) {
        ecs_bitset_remove(&bs_columns[i].data, index);
    }    
}

static
void fast_move(
    ecs_table_t * new_table,
    ecs_data_t * new_data,
    int32_t new_index,
    ecs_table_t * old_table,
    ecs_data_t * old_data,
    int32_t old_index)
{
    ecs_type_t new_type = new_table->type;
    ecs_type_t old_type = old_table->type;

    int32_t i_new = 0, new_column_count = new_table->column_count;
    int32_t i_old = 0, old_column_count = old_table->column_count;
    ecs_entity_t *new_components = ecs_vector_first(new_type, ecs_entity_t);
    ecs_entity_t *old_components = ecs_vector_first(old_type, ecs_entity_t);

    ecs_column_t *old_columns = old_data->columns;
    ecs_column_t *new_columns = new_data->columns;

    for (; (i_new < new_column_count) && (i_old < old_column_count);) {
        ecs_entity_t new_component = new_components[i_new];
        ecs_entity_t old_component = old_components[i_old];

        if (new_component == old_component) {
            ecs_column_t *new_column = &new_columns[i_new];
            ecs_column_t *old_column = &old_columns[i_old];
            int16_t size = new_column->size;

            if (size) {
                int16_t alignment = new_column->alignment;
                void *dst = ecs_vector_get_t(new_column->data, size, alignment, new_index);
                void *src = ecs_vector_get_t(old_column->data, size, alignment, old_index);

                ecs_assert(dst != NULL, ECS_INTERNAL_ERROR, NULL);
                ecs_assert(src != NULL, ECS_INTERNAL_ERROR, NULL);
                ecs_os_memcpy(dst, src, size); 
            }
        }

        i_new += new_component <= old_component;
        i_old += new_component >= old_component;
    }
}

void ecs_table_move(
    ecs_world_t *world,
    ecs_entity_t dst_entity,
    ecs_entity_t src_entity,
    ecs_table_t *new_table,
    ecs_data_t *new_data,
    int32_t new_index,
    ecs_table_t *old_table,
    ecs_data_t *old_data,
    int32_t old_index)
{
    ecs_assert(new_table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(old_table != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_assert(old_index >= 0, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(new_index >= 0, ECS_INTERNAL_ERROR, NULL);

    ecs_assert(old_data != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(new_data != NULL, ECS_INTERNAL_ERROR, NULL);

    if (!((new_table->flags | old_table->flags) & EcsTableIsComplex)) {
        fast_move(new_table, new_data, new_index, old_table, old_data, old_index);
        return;
    }

    move_switch_columns(
        new_table, new_data, new_index, old_table, old_data, old_index, 1);

    move_bitset_columns(
        new_table, new_data, new_index, old_table, old_data, old_index, 1);

    bool same_entity = dst_entity == src_entity;

    ecs_type_t new_type = new_table->type;
    ecs_type_t old_type = old_table->type;

    int32_t i_new = 0, new_column_count = new_table->column_count;
    int32_t i_old = 0, old_column_count = old_table->column_count;
    ecs_entity_t *new_components = ecs_vector_first(new_type, ecs_entity_t);
    ecs_entity_t *old_components = ecs_vector_first(old_type, ecs_entity_t);

    ecs_column_t *old_columns = old_data->columns;
    ecs_column_t *new_columns = new_data->columns;

    for (; (i_new < new_column_count) && (i_old < old_column_count);) {
        ecs_entity_t new_component = new_components[i_new];
        ecs_entity_t old_component = old_components[i_old];

        if (new_component == old_component) {
            ecs_column_t *new_column = &new_columns[i_new];
            ecs_column_t *old_column = &old_columns[i_old];
            int16_t size = new_column->size;
            int16_t alignment = new_column->alignment;

            if (size) {
                void *dst = ecs_vector_get_t(new_column->data, size, alignment, new_index);
                void *src = ecs_vector_get_t(old_column->data, size, alignment, old_index);

                ecs_assert(dst != NULL, ECS_INTERNAL_ERROR, NULL);
                ecs_assert(src != NULL, ECS_INTERNAL_ERROR, NULL);

                ecs_type_info_t *cdata = new_table->c_info[i_new];
                if (same_entity) {
                    ecs_move_t move;
                    if (cdata && (move = cdata->lifecycle.move)) {
                        void *ctx = cdata->lifecycle.ctx;
                        ecs_xtor_t ctor = cdata->lifecycle.ctor;

                        /* Ctor should always be set if copy is set */
                        ecs_assert(ctor != NULL, ECS_INTERNAL_ERROR, NULL);

                        /* Construct a new value, move the value to it */
                        ctor(world, new_component, &dst_entity, dst, 
                                ecs_to_size_t(size), 1, ctx);

                        move(world, new_component, &dst_entity, &src_entity, 
                            dst, src, ecs_to_size_t(size), 1, ctx);
                    } else {
                        ecs_os_memcpy(dst, src, size);
                    }
                } else {
                    ecs_copy_t copy;
                    if (cdata && (copy = cdata->lifecycle.copy)) {
                        void *ctx = cdata->lifecycle.ctx;
                        ecs_xtor_t ctor = cdata->lifecycle.ctor;

                        /* Ctor should always be set if copy is set */
                        ecs_assert(ctor != NULL, ECS_INTERNAL_ERROR, NULL);
                        ctor(world, new_component, &dst_entity, dst, 
                            ecs_to_size_t(size), 1, ctx);
                        copy(world, new_component, &dst_entity, &src_entity, 
                            dst, src, ecs_to_size_t(size), 1, ctx);
                    } else {
                        ecs_os_memcpy(dst, src, size);
                    }
                }
            }
        } else {
            if (new_component < old_component) {
                ctor_component(world, new_table->c_info[i_new],
                    &new_columns[i_new], &dst_entity, new_index, 1);
            } else {
                dtor_component(world, old_table->c_info[i_old],
                    &old_columns[i_old], &src_entity, old_index, 1);
            }
        }

        i_new += new_component <= old_component;
        i_old += new_component >= old_component;
    }

    for (; (i_new < new_column_count); i_new ++) {
        ctor_component(world, new_table->c_info[i_new],
            &new_columns[i_new], &dst_entity, new_index, 1);
    }

    for (; (i_old < old_column_count); i_old ++) {
        dtor_component(world, old_table->c_info[i_old],
            &old_columns[i_old], &src_entity, old_index, 1);
    }
}

int32_t ecs_table_appendn(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t * data,
    int32_t to_add,
    const ecs_entity_t *ids)
{
    int32_t cur_count = ecs_table_data_count(data);
    return grow_data(world, table, data, to_add, cur_count + to_add, ids);
}

void ecs_table_set_size(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t * data,
    int32_t size)
{
    int32_t cur_count = ecs_table_data_count(data);

    if (cur_count < size) {
        grow_data(world, table, data, 0, size, NULL);
    } else if (!size) {
        /* Initialize columns if 0 is passed. This is a shortcut to initialize
         * columns when, for example, an API call is inserting bulk data. */
        int32_t column_count = table->column_count;
        int32_t sw_column_count = table->sw_column_count;
        int32_t bs_column_count = table->bs_column_count;
        ecs_column_t *columns;
        ecs_sw_column_t *sw_columns;
        ecs_bs_column_t *bs_columns;
        ensure_data(world, table, data, &column_count, &sw_column_count,
            &bs_column_count, &columns, &sw_columns, &bs_columns);
    }
}

int32_t ecs_table_data_count(
    const ecs_data_t *data)
{
    return data ? ecs_vector_count(data->entities) : 0;
}

static
void swap_switch_columns(
    ecs_table_t *table,
    ecs_data_t * data,
    int32_t row_1,
    int32_t row_2)
{
    int32_t i = 0, column_count = table->sw_column_count;
    if (!column_count) {
        return;
    }

    ecs_sw_column_t *columns = data->sw_columns;

    for (i = 0; i < column_count; i ++) {
        ecs_switch_t *sw = columns[i].data;
        ecs_switch_swap(sw, row_1, row_2);
    }
}

static
void swap_bitset_columns(
    ecs_table_t *table,
    ecs_data_t * data,
    int32_t row_1,
    int32_t row_2)
{
    int32_t i = 0, column_count = table->bs_column_count;
    if (!column_count) {
        return;
    }

    ecs_bs_column_t *columns = data->bs_columns;

    for (i = 0; i < column_count; i ++) {
        ecs_bitset_t *bs = &columns[i].data;
        ecs_bitset_swap(bs, row_1, row_2);
    }
}

void ecs_table_swap(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t * data,
    int32_t row_1,
    int32_t row_2)
{    
    (void)world;

    ecs_assert(data != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_column_t *columns = data->columns;
    ecs_assert(columns != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_assert(row_1 >= 0, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(row_2 >= 0, ECS_INTERNAL_ERROR, NULL);
    
    if (row_1 == row_2) {
        return;
    }

    ecs_entity_t *entities = ecs_vector_first(data->entities, ecs_entity_t);
    ecs_entity_t e1 = entities[row_1];
    ecs_entity_t e2 = entities[row_2];

    ecs_record_t **record_ptrs = ecs_vector_first(data->record_ptrs, ecs_record_t*);
    ecs_record_t *record_ptr_1 = record_ptrs[row_1];
    ecs_record_t *record_ptr_2 = record_ptrs[row_2];

    ecs_assert(record_ptr_1 != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(record_ptr_2 != NULL, ECS_INTERNAL_ERROR, NULL);

    /* Swap entities */
    entities[row_1] = e2;
    entities[row_2] = e1;
    record_ptr_1->row = row_2;
    record_ptr_2->row = row_1;
    record_ptrs[row_1] = record_ptr_2;
    record_ptrs[row_2] = record_ptr_1;

    if (row_2 < 0) {
        record_ptr_1->row --;
    } else {
        record_ptr_1->row ++;
    }
    if (row_1 < 0) {
        record_ptr_2->row --;
    } else {
        record_ptr_2->row ++;
    }    

    /* Swap columns */
    int32_t i, column_count = table->column_count;
    
    for (i = 0; i < column_count; i ++) {
        int16_t size = columns[i].size;
        int16_t alignment = columns[i].alignment;
        void *ptr = ecs_vector_first_t(columns[i].data, size, alignment);

        if (size) {
            void *tmp = ecs_os_alloca(size);

            void *el_1 = ECS_OFFSET(ptr, size * row_1);
            void *el_2 = ECS_OFFSET(ptr, size * row_2);

            ecs_os_memcpy(tmp, el_1, size);
            ecs_os_memcpy(el_1, el_2, size);
            ecs_os_memcpy(el_2, tmp, size);
        }
    }

    swap_switch_columns(table, data, row_1, row_2);
    swap_bitset_columns(table, data, row_1, row_2);

    /* If the table is monitored indicate that there has been a change */
    mark_table_dirty(table, 0);    
}

static
void merge_vector(
    ecs_vector_t **dst_out,
    ecs_vector_t *src,
    int16_t size,
    int16_t alignment)
{
    ecs_vector_t *dst = *dst_out;
    int32_t dst_count = ecs_vector_count(dst);

    if (!dst_count) {
        if (dst) {
            ecs_vector_free(dst);
        }

        *dst_out = src;
    
    /* If the new table is not empty, copy the contents from the
     * src into the dst. */
    } else {
        int32_t src_count = ecs_vector_count(src);
        ecs_vector_set_count_t(&dst, size, alignment, dst_count + src_count);
        
        void *dst_ptr = ecs_vector_first_t(dst, size, alignment);
        void *src_ptr = ecs_vector_first_t(src, size, alignment);

        dst_ptr = ECS_OFFSET(dst_ptr, size * dst_count);
        
        ecs_os_memcpy(dst_ptr, src_ptr, size * src_count);

        ecs_vector_free(src);
        *dst_out = dst;
    }
}

static
void merge_column(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data,
    int32_t column_id,
    ecs_vector_t *src)
{
    ecs_entity_t *entities = ecs_vector_first(data->entities, ecs_entity_t);
    ecs_type_info_t *c_info = table->c_info[column_id];
    ecs_column_t *column = &data->columns[column_id];
    ecs_vector_t *dst = column->data;
    int16_t size = column->size;
    int16_t alignment = column->alignment;
    int32_t dst_count = ecs_vector_count(dst);

    if (!dst_count) {
        if (dst) {
            ecs_vector_free(dst);
        }

        column->data = src;
    
    /* If the new table is not empty, copy the contents from the
     * src into the dst. */
    } else {
        int32_t src_count = ecs_vector_count(src);
        ecs_vector_set_count_t(&dst, size, alignment, dst_count + src_count);
        column->data = dst;

        /* Construct new values */
        if (c_info) {
            ctor_component(
                world, c_info, column, entities, dst_count, src_count);
        }
        
        void *dst_ptr = ecs_vector_first_t(dst, size, alignment);
        void *src_ptr = ecs_vector_first_t(src, size, alignment);

        dst_ptr = ECS_OFFSET(dst_ptr, size * dst_count);
        
        /* Move values into column */
        ecs_move_t move;
        if (c_info && (move = c_info->lifecycle.move)) {
            move(world, c_info->component, entities, entities, 
                dst_ptr, src_ptr, ecs_to_size_t(size), src_count, 
                c_info->lifecycle.ctx);
        } else {
            ecs_os_memcpy(dst_ptr, src_ptr, size * src_count);
        }

        ecs_vector_free(src);
    }
}

static
void merge_table_data(
    ecs_world_t *world,
    ecs_table_t * new_table,
    ecs_table_t * old_table,
    int32_t old_count,
    int32_t new_count,
    ecs_data_t * old_data,
    ecs_data_t * new_data)
{
    int32_t i_new, new_component_count = new_table->column_count;
    int32_t i_old = 0, old_component_count = old_table->column_count;
    ecs_entity_t *new_components = ecs_vector_first(new_table->type, ecs_entity_t);
    ecs_entity_t *old_components = ecs_vector_first(old_table->type, ecs_entity_t);

    ecs_column_t *old_columns = old_data->columns;
    ecs_column_t *new_columns = new_data->columns;

    if (!new_columns && !new_data->entities) {
        ecs_init_data(world, new_table, new_data);
        new_columns = new_data->columns;
    }

    if (!old_count) {
        return;
    }

    /* Merge entities */
    merge_vector(&new_data->entities, old_data->entities, ECS_SIZEOF(ecs_entity_t), 
        ECS_ALIGNOF(ecs_entity_t));
    old_data->entities = NULL;
    ecs_entity_t *entities = ecs_vector_first(new_data->entities, ecs_entity_t);

    ecs_assert(ecs_vector_count(new_data->entities) == old_count + new_count, 
        ECS_INTERNAL_ERROR, NULL);

    /* Merge entity index record pointers */
    merge_vector(&new_data->record_ptrs, old_data->record_ptrs, 
        ECS_SIZEOF(ecs_record_t*), ECS_ALIGNOF(ecs_record_t*));
    old_data->record_ptrs = NULL;        

    for (i_new = 0; (i_new < new_component_count) && (i_old < old_component_count); ) {
        ecs_entity_t new_component = new_components[i_new];
        ecs_entity_t old_component = old_components[i_old];
        int16_t size = new_columns[i_new].size;
        int16_t alignment = new_columns[i_new].alignment;

        if ((new_component & ECS_ROLE_MASK) || 
            (old_component & ECS_ROLE_MASK)) 
        {
            break;
        }

        if (new_component == old_component) {
            merge_column(world, new_table, new_data, i_new, 
                old_columns[i_old].data);
            old_columns[i_old].data = NULL;

            /* Mark component column as dirty */
            mark_table_dirty(new_table, i_new + 1);
            
            i_new ++;
            i_old ++;
        } else if (new_component < old_component) {
            /* New column does not occur in old table, make sure vector is large
             * enough. */
            if (size) {
                ecs_column_t *column = &new_columns[i_new];
                ecs_vector_set_count_t(&column->data, size, alignment,
                    old_count + new_count);

                /* Construct new values */
                ecs_type_info_t *c_info;
                ecs_xtor_t ctor;
                if ((c_info = new_table->c_info[i_new]) && 
                    (ctor = c_info->lifecycle.ctor)) 
                {
                    ctor_component(world, c_info, column, 
                        entities, 0, old_count + new_count);
                }
            }
            
            i_new ++;
        } else if (new_component > old_component) {
            if (size) {
                ecs_column_t *column = &old_columns[i_old];
                
                /* Destruct old values */
                ecs_type_info_t *c_info;
                ecs_xtor_t dtor;
                if ((c_info = old_table->c_info[i_old]) && 
                    (dtor = c_info->lifecycle.dtor)) 
                {
                    dtor_component(world, c_info, column, 
                        entities, 0, old_count);
                }

                /* Old column does not occur in new table, remove */
                ecs_vector_free(column->data);
                column->data = NULL;

                i_old ++;
            }
        }
    }

    move_switch_columns(
        new_table, new_data, new_count, old_table, old_data, 0, old_count);

    /* Initialize remaining columns */
    for (; i_new < new_component_count; i_new ++) {
        ecs_column_t *column = &new_columns[i_new];
        int16_t size = column->size;
        int16_t alignment = column->alignment;

        if (size) {
            ecs_vector_set_count_t(&column->data, size, alignment,
                old_count + new_count);

            /* Construct new values */
            ecs_type_info_t *c_info;
            ecs_xtor_t ctor;
            if ((c_info = new_table->c_info[i_new]) && 
                (ctor = c_info->lifecycle.ctor)) 
            {
                ctor_component(world, c_info, column, 
                    entities, 0, old_count + new_count);
            }
        }
    }

    /* Destroy remaining columns */
    for (; i_old < old_component_count; i_old ++) {
        ecs_column_t *column = &old_columns[i_old];
                
        /* Destruct old values */
        ecs_type_info_t *c_info;
        ecs_xtor_t dtor;
        if ((c_info = old_table->c_info[i_old]) && 
            (dtor = c_info->lifecycle.dtor)) 
        {
            dtor_component(world, c_info, column, entities, 
                0, old_count);
        }

        /* Old column does not occur in new table, remove */
        ecs_vector_free(column->data);
        column->data = NULL;
    }    

    /* Mark entity column as dirty */
    mark_table_dirty(new_table, 0); 
}

int32_t ecs_table_count(
    const ecs_table_t *table)
{
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_data_t *data = table->data;
    if (!data) {
        return 0;
    }

    return ecs_table_data_count(data);
}

ecs_data_t* ecs_table_merge(
    ecs_world_t *world,
    ecs_table_t *new_table,
    ecs_table_t *old_table,
    ecs_data_t *new_data,
    ecs_data_t *old_data)
{
    ecs_assert(old_table != NULL, ECS_INTERNAL_ERROR, NULL);
    bool move_data = false;
    
    /* If there is nothing to merge to, just clear the old table */
    if (!new_table) {
        ecs_table_clear_data(world, old_table, old_data);
        return NULL;
    }

    /* If there is no data to merge, drop out */
    if (!old_data) {
        return NULL;
    }

    if (!new_data) {
        new_data = ecs_table_get_or_create_data(new_table);
        if (new_table == old_table) {
            move_data = true;
        }
    }

    ecs_entity_t *old_entities = ecs_vector_first(old_data->entities, ecs_entity_t);

    int32_t old_count = ecs_vector_count(old_data->entities);
    int32_t new_count = ecs_vector_count(new_data->entities);

    ecs_record_t **old_records = ecs_vector_first(
        old_data->record_ptrs, ecs_record_t*);

    /* First, update entity index so old entities point to new type */
    int32_t i;
    for(i = 0; i < old_count; i ++) {
        ecs_record_t *record;
        if (new_table != old_table) {
            record = old_records[i];
            ecs_assert(record != NULL, ECS_INTERNAL_ERROR, NULL);
        } else {
            record = ecs_eis_ensure(world, old_entities[i]);
        }

        bool is_monitored = record->row < 0;
        record->row = ecs_row_to_record(new_count + i, is_monitored);
        record->table = new_table;
    }

    /* Merge table columns */
    if (move_data) {
        *new_data = *old_data;
    } else {
        merge_table_data(world, new_table, old_table, old_count, new_count, 
            old_data, new_data);
    }

    new_table->alloc_count ++;

    if (!new_count && old_count) {
        ecs_table_activate(world, new_table, NULL, true);
    }

    return new_data;
}

void ecs_table_replace_data(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t * data)
{
    int32_t prev_count = 0;
    ecs_data_t *table_data = table->data;
    ecs_assert(!data || data != table_data, ECS_INTERNAL_ERROR, NULL);

    if (table_data) {
        prev_count = ecs_vector_count(table_data->entities);
        run_remove_actions(world, table, 0, ecs_table_data_count(table_data));
        ecs_table_clear_data(world, table, table_data);
    }

    if (data) {
        table_data = ecs_table_get_or_create_data(table);
        *table_data = *data;
    } else {
        return;
    }

    int32_t count = ecs_table_count(table);

    if (!prev_count && count) {
        ecs_table_activate(world, table, 0, true);
    } else if (prev_count && !count) {
        ecs_table_activate(world, table, 0, false);
    }
}

bool ecs_table_match_filter(
    const ecs_world_t *world,
    const ecs_table_t *table,
    const ecs_filter_t * filter)
{
    if (!filter) {
        return true;
    }

    ecs_type_t type = table->type;
    
    if (filter->include) {
        /* If filter kind is exact, types must be the same */
        if (filter->include_kind == EcsMatchExact) {
            if (type != filter->include) {
                return false;
            }

        /* Default for include_kind is MatchAll */
        } else if (!ecs_type_contains(world, type, filter->include, 
            filter->include_kind != EcsMatchAny, true)) 
        {
            return false;
        }
    }

    if (filter->exclude) {
        /* If filter kind is exact, types must be the same */
        if (filter->exclude_kind == EcsMatchExact) {
            if (type == filter->exclude) {
                return false;
            }
        
        /* Default for exclude_kind is MatchAny */                
        } else if (ecs_type_contains(world, type, filter->exclude, 
            filter->exclude_kind == EcsMatchAll, true))
        {
            return false;
        }
    }

    return true;
}

int32_t* ecs_table_get_dirty_state(
    ecs_table_t *table)
{
    if (!table->dirty_state) {
        table->dirty_state = ecs_os_calloc(ECS_SIZEOF(int32_t) * (table->column_count + 1));
        ecs_assert(table->dirty_state != NULL, ECS_INTERNAL_ERROR, NULL);
    }
    return table->dirty_state;
}

int32_t* ecs_table_get_monitor(
    ecs_table_t *table)
{
    int32_t *dirty_state = ecs_table_get_dirty_state(table);
    ecs_assert(dirty_state != NULL, ECS_INTERNAL_ERROR, NULL);

    int32_t column_count = table->column_count;
    return ecs_os_memdup(dirty_state, (column_count + 1) * ECS_SIZEOF(int32_t));
}

void ecs_table_notify(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_table_event_t * event)
{
    if (world->is_fini) {
        return;
    }

    switch(event->kind) {
    case EcsTableQueryMatch:
        register_query(
            world, table, event->query, event->matched_table_index);
        break;
    case EcsTableQueryUnmatch:
        unregister_query(
            world, table, event->query);
        break;
    case EcsTableComponentInfo:
        notify_component_info(world, table, event->component);
        break;
    case EcsTableTriggerMatch:
        notify_trigger(world, table, event->event);
        break;
    }
}


static
const ecs_entity_t* new_w_data(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_entities_t *component_ids,
    int32_t count,
    void **c_info,
    int32_t *row_out);

static 
void* get_component_w_index(
    ecs_entity_info_t *info,
    int32_t index)
{
    ecs_data_t *data = info->data;
    ecs_assert(data != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_column_t *columns = data->columns;
    ecs_assert(columns != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(index < info->table->column_count, ECS_INVALID_COMPONENT_ID, NULL);

    ecs_column_t *column = &columns[index];
    ecs_vector_t *data_vec = column->data;
    int16_t size = column->size; 
    
    /* If size is 0, component does not have a value. This is likely caused by
     * an application trying to call ecs_get with a tag. */
    ecs_assert(size != 0, ECS_INVALID_PARAMETER, NULL);

    /* This function should not be called if an entity does not exist in the
     * provided table. Therefore if the component is found in the table, and an
     * entity exists for it, the vector cannot be NULL */
    ecs_assert(data_vec != NULL, ECS_INTERNAL_ERROR, NULL);

    void *ptr = ecs_vector_first_t(data_vec, size, column->alignment);

    /* This could only happen when the vector is empty, which should not be
     * possible since the vector should at least have one element */
    ecs_assert(ptr != NULL, ECS_INTERNAL_ERROR, NULL);

    return ECS_OFFSET(ptr, info->row * size);
}

/* Get pointer to single component value */
static
void* get_component(
    ecs_entity_info_t *info,
    ecs_entity_t component)
{
    ecs_assert(info->table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(component != 0, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(info->row >= 0, ECS_INTERNAL_ERROR, NULL);

    ecs_table_t *table = info->table;
    ecs_type_t type = table->type;

    ecs_entity_t *ids = ecs_vector_first(type, ecs_entity_t);

    /* The table column_count contains the maximum column index that actually
     * contains data. This excludes component ids that do not have data, such
     * as tags. Therefore it is faster to iterate column_count vs. all the
     * elements in the type.
     *
     * The downside of this is that the code can't always detect when an 
     * application attempts to get the value of a tag (which is not allowed). To
     * ensure consistent behavior in debug mode, the entire type is iterated as
     * this guarantees that the code will assert when attempting to obtain the
     * value of a tag. */
#ifndef NDEBUG
    int i, count = ecs_vector_count(type);
#else
    int i, count = table->column_count;
#endif

    for (i = 0; i < count; i ++) {
        if (ids[i] == component) {
            return get_component_w_index(info, i);
        }
    }

    return NULL;
}

/* Utility to compute actual row from row in record */
static
int32_t set_row_info(
    ecs_entity_info_t *info,
    int32_t row)
{
    return info->row = ecs_record_to_row(row, &info->is_watched);
}

/* Utility to set info from main stage record */
static
void set_info_from_record(
    ecs_entity_t e,
    ecs_entity_info_t * info,
    ecs_record_t * record)
{
    (void)e;
    
    ecs_assert(record != NULL, ECS_INTERNAL_ERROR, NULL);

    info->record = record;

    ecs_table_t *table = record->table;

    set_row_info(info, record->row);

    info->table = table;
    if (!info->table) {
        return;
    }

    ecs_data_t *data = ecs_table_get_data(table);
    ecs_assert(data != NULL, ECS_INTERNAL_ERROR, NULL);

    info->data = data;

    ecs_assert(ecs_vector_count(data->entities) > info->row, 
        ECS_INTERNAL_ERROR, NULL);
}

/* Get info from main stage */
bool ecs_get_info(
    const ecs_world_t * world,
    ecs_entity_t entity,
    ecs_entity_info_t * info)
{
    info->table = NULL;
    info->record = NULL;
    info->data = NULL;
    info->is_watched = false;

    if (entity & ECS_ROLE) {
        return false;
    }
    
    ecs_record_t *record = ecs_eis_get(world, entity);

    if (!record) {
        return false;
    }

    set_info_from_record(entity, info, record);

    return true;
}

static
const ecs_type_info_t *get_c_info(
    ecs_world_t *world,
    ecs_entity_t component)
{
    ecs_entity_t real_id = ecs_get_typeid(world, component);
    if (real_id) {
        return ecs_get_c_info(world, real_id);
    } else {
        return NULL;
    }
}

void ecs_get_column_info(
    ecs_world_t * world,
    ecs_table_t * table,
    ecs_entities_t * components,
    ecs_column_info_t * cinfo,
    bool get_all)
{
    int32_t column_count = table->column_count;
    ecs_entity_t *type_array = ecs_vector_first(table->type, ecs_entity_t);

    if (get_all) {
        int32_t i, count = ecs_vector_count(table->type);
        for (i = 0; i < count; i ++) {
            ecs_entity_t id = type_array[i];
            cinfo[i].id = id;
            cinfo[i].ci = get_c_info(world, id);
            cinfo[i].column = i;            
        }
    } else {
        ecs_entity_t *array = components->array;
        int32_t i, cur, count = components->count;
        for (i = 0; i < count; i ++) {
            ecs_entity_t id = array[i];
            cinfo[i].id = id;
            cinfo[i].ci = get_c_info(world, id);
            cinfo[i].column = -1;

            for (cur = 0; cur < column_count; cur ++) {
                if (type_array[cur] == id) {
                    cinfo[i].column = cur;
                    break;
                }
            }
        }
    }
}

#ifdef FLECS_SYSTEM 
static
void run_set_systems_for_entities(
    ecs_world_t * world,
    ecs_entities_t * components,
    ecs_table_t * table,
    int32_t row,
    int32_t count,
    ecs_entity_t * entities,
    bool set_all)
{   
    if (set_all) {
        /* Run OnSet systems for all components of the entity. This usually
         * happens when an entity is created directly in its target table. */
        ecs_vector_t *queries = table->on_set_all;
        ecs_vector_each(queries, ecs_matched_query_t, m, {
            ecs_run_monitor(world, m, components, row, count, entities);
        });
    } else {
        /* Run OnSet systems for a specific component. This usually happens when
         * an application calls ecs_set or ecs_modified. The entity's table
         * stores a vector for each component with the OnSet systems for that
         * component. This vector maintains the same order as the table's type,
         * which makes finding the correct set of systems as simple as getting
         * the index of a component id in the table type. 
         *
         * One thing to note is that the system may be invoked for a table that
         * is not the same as the entity for which the system is invoked. This
         * can happen in the case of instancing, where adding an IsA
         * relationship conceptually adds components to an entity, but the 
         * actual components are stored on the base entity. */
        ecs_vector_t **on_set_systems = table->on_set;
        if (on_set_systems) {
            int32_t index = ecs_type_index_of(table->type, components->array[0]);
            
            /* This should never happen, as an OnSet system should only ever be
             * invoked for entities that have the component for which this
             * function was invoked. */
            ecs_assert(index != -1, ECS_INTERNAL_ERROR, NULL);

            ecs_vector_t *queries = on_set_systems[index];
            ecs_vector_each(queries, ecs_matched_query_t, m, {
                ecs_run_monitor(world, m, components, row, count, entities);
            });
        }
    }
}
#endif

void ecs_run_set_systems(
    ecs_world_t * world,
    ecs_entities_t * components,
    ecs_table_t * table,
    ecs_data_t * data,
    int32_t row,
    int32_t count,
    bool set_all)
{
    (void)world;
    (void)components;
    (void)table;
    (void)data;
    (void)row;
    (void)count;
    (void)set_all;

#ifdef FLECS_SYSTEM    
    if (!count || !data) {
        return;
    }
    
    ecs_entity_t *entities = ecs_vector_first(data->entities, ecs_entity_t);        
    ecs_assert(entities != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(row < ecs_vector_count(data->entities), ECS_INTERNAL_ERROR, NULL);
    ecs_assert((row + count) <= ecs_vector_count(data->entities), ECS_INTERNAL_ERROR, NULL);

    entities = ECS_OFFSET(entities, ECS_SIZEOF(ecs_entity_t) * row);

    run_set_systems_for_entities(world, components, table, row, 
        count, entities, set_all);
#endif
}

void ecs_run_monitors(
    ecs_world_t * world, 
    ecs_table_t * dst_table,
    ecs_vector_t * v_dst_monitors, 
    int32_t dst_row, 
    int32_t count, 
    ecs_vector_t *v_src_monitors)
{
    (void)world;
    (void)dst_table;
    (void)v_dst_monitors;
    (void)dst_row;
    (void)count;
    (void)v_src_monitors;

#ifdef FLECS_SYSTEM    
    if (v_dst_monitors == v_src_monitors) {
        return;
    }

    if (!v_dst_monitors) {
        return;
    }

    ecs_assert(!(dst_table->flags & EcsTableIsPrefab), ECS_INTERNAL_ERROR, NULL);
    
    if (!v_src_monitors) {
        ecs_vector_each(v_dst_monitors, ecs_matched_query_t, monitor, {
            ecs_run_monitor(world, monitor, NULL, dst_row, count, NULL);
        });
    } else {
        /* If both tables have monitors, run the ones that dst_table has and
         * src_table doesn't have */
        int32_t i, m_count = ecs_vector_count(v_dst_monitors);
        int32_t j = 0, src_count = ecs_vector_count(v_src_monitors);
        ecs_matched_query_t *dst_monitors = ecs_vector_first(v_dst_monitors, ecs_matched_query_t);
        ecs_matched_query_t *src_monitors = ecs_vector_first(v_src_monitors, ecs_matched_query_t);

        for (i = 0; i < m_count; i ++) {
            ecs_matched_query_t *dst = &dst_monitors[i];

            ecs_entity_t system = dst->query->system;
            ecs_assert(system != 0, ECS_INTERNAL_ERROR, NULL);

            ecs_matched_query_t *src = 0;
            while (j < src_count) {
                src = &src_monitors[j];
                if (src->query->system < system) {
                    j ++;
                } else {
                    break;
                }
            }

            if (src && src->query->system == system) {
                continue;
            }

            ecs_run_monitor(world, dst, NULL, dst_row, count, NULL);
        }
    }
#endif
}

static
int32_t find_prefab(
    ecs_type_t type,
    int32_t n)
{
    int32_t i, count = ecs_vector_count(type);
    ecs_entity_t *buffer = ecs_vector_first(type, ecs_entity_t);

    for (i = n + 1; i < count; i ++) {
        ecs_entity_t e = buffer[i];
        if (ECS_HAS_RELATION(e, EcsIsA)) {
            return i;
        }
    }

    return -1;
}

static
void instantiate(
    ecs_world_t *world,
    ecs_entity_t base,
    ecs_table_t *table,
    ecs_data_t *data,
    int32_t row,
    int32_t count);

static
void instantiate_children(
    ecs_world_t * world,
    ecs_entity_t base,
    ecs_table_t * table,
    ecs_data_t * data,
    int32_t row,
    int32_t count,
    ecs_table_t * child_table)
{
    ecs_type_t type = child_table->type;
    ecs_data_t *child_data = ecs_table_get_data(child_table);
    if (!child_data || !ecs_table_data_count(child_data)) {
        return;
    }

    int32_t column_count = child_table->column_count;
    ecs_entity_t *type_array = ecs_vector_first(type, ecs_entity_t);
    int32_t type_count = ecs_vector_count(type);   

    /* Instantiate child table for each instance */

    /* Create component array for creating the table */
    ecs_entities_t components = {
        .array = ecs_os_alloca(ECS_SIZEOF(ecs_entity_t) * type_count + 1)
    };

    void **c_info = ecs_os_alloca(ECS_SIZEOF(void*) * column_count);

    /* Copy in component identifiers. Find the base index in the component
     * array, since we'll need this to replace the base with the instance id */
    int i, base_index = -1, pos = 0;

    for (i = 0; i < type_count; i ++) {
        ecs_entity_t c = type_array[i];
        
        /* Make sure instances don't have EcsPrefab */
        if (c == EcsPrefab) {
            continue;
        }

        /* Keep track of the element that creates the ChildOf relationship with
        * the prefab parent. We need to replace this element to make sure the
        * created children point to the instance and not the prefab */ 
        if (ECS_HAS_RELATION(c, EcsChildOf) && (ecs_entity_t_lo(c) == base)) {
            base_index = pos;
        }        

        /* Store pointer to component array. We'll use this component array to
        * create our new entities in bulk with new_w_data */
        if (i < column_count) {
            ecs_column_t *column = &child_data->columns[i];
            c_info[pos] = ecs_vector_first_t(
                column->data, column->size, column->alignment);
        }

        components.array[pos] = c;
        pos ++;
    }

    ecs_assert(base_index != -1, ECS_INTERNAL_ERROR, NULL);

    /* If children are added to a prefab, make sure they are prefabs too */
    if (table->flags & EcsTableIsPrefab) {
        components.array[pos] = EcsPrefab;
        pos ++;
    }

    components.count = pos;

    /* Instantiate the prefab child table for each new instance */
    ecs_entity_t *entities = ecs_vector_first(data->entities, ecs_entity_t);
    int32_t child_count = ecs_vector_count(child_data->entities);

    for (i = row; i < count + row; i ++) {
        ecs_entity_t instance = entities[i];

        /* Replace ChildOf element in the component array with instance id */
        components.array[base_index] = ecs_pair(EcsChildOf, instance);

        /* Find or create table */
        ecs_table_t *i_table = ecs_table_find_or_create(world, &components);
        ecs_assert(i_table != NULL, ECS_INTERNAL_ERROR, NULL); 

        /* The instance is trying to instantiate from a base that is also
         * its parent. This would cause the hierarchy to instantiate itself
         * which would cause infinite recursion. */
        int j;
        ecs_entity_t *children = ecs_vector_first(
            child_data->entities, ecs_entity_t);
#ifndef NDEBUG
        for (j = 0; j < child_count; j ++) {
            ecs_entity_t child = children[j];        
            ecs_assert(child != instance, ECS_INVALID_PARAMETER, NULL);
        }
#endif

        /* Create children */
        int32_t child_row; 
        new_w_data(world, i_table, NULL, child_count, c_info, &child_row);       

        /* If prefab child table has children itself, recursively instantiate */
        ecs_data_t *i_data = ecs_table_get_data(i_table);
        for (j = 0; j < child_count; j ++) {
            ecs_entity_t child = children[j];
            instantiate(world, child, i_table, i_data, child_row + j, 1);
        }
    }       
}

static
void instantiate(
    ecs_world_t * world,
    ecs_entity_t base,
    ecs_table_t * table,
    ecs_data_t * data,
    int32_t row,
    int32_t count)
{    
    /* If base is a parent, instantiate children of base for instances */
    const ecs_id_record_t *r = ecs_get_id_record(
        world, ecs_pair(EcsChildOf, base));

    if (r && r->table_index) {
        ecs_table_record_t *tr;
        ecs_map_iter_t it = ecs_map_iter(r->table_index);
        while ((tr = ecs_map_next(&it, ecs_table_record_t, NULL))) {
            instantiate_children(
                world, base, table, data, row, count, tr->table);
        }
    }
}

static
bool override_component(
    ecs_world_t *world,
    ecs_entity_t component,
    ecs_type_t type,
    ecs_data_t *data,
    ecs_column_t *column,
    int32_t row,
    int32_t count);

static
bool override_from_base(
    ecs_world_t * world,
    ecs_entity_t base,
    ecs_entity_t component,
    ecs_data_t * data,
    ecs_column_t * column,
    int32_t row,
    int32_t count)
{
    ecs_entity_info_t base_info;
    ecs_assert(component != 0, ECS_INTERNAL_ERROR, NULL);

    if (!ecs_get_info(world, base, &base_info) || !base_info.table) {
        return false;
    }

    void *base_ptr = get_component(&base_info, component);
    if (base_ptr) {
        int16_t data_size = column->size;
        void *data_array = ecs_vector_first_t(
            column->data, column->size, column->alignment);
        void *data_ptr = ECS_OFFSET(data_array, data_size * row);

        component = ecs_get_typeid(world, component);
        const ecs_type_info_t *cdata = ecs_get_c_info(world, component);
        int32_t index;

        ecs_copy_t copy = cdata ? cdata->lifecycle.copy : NULL;
        if (copy) {
            ecs_entity_t *entities = ecs_vector_first(
                data->entities, ecs_entity_t);

            void *ctx = cdata->lifecycle.ctx;
            for (index = 0; index < count; index ++) {
                copy(world, component, &entities[row], &base,
                    data_ptr, base_ptr, ecs_to_size_t(data_size), 1, ctx);
                data_ptr = ECS_OFFSET(data_ptr, data_size);
            }
        } else {
            for (index = 0; index < count; index ++) {
                ecs_os_memcpy(data_ptr, base_ptr, data_size);
                data_ptr = ECS_OFFSET(data_ptr, data_size);
            }                    
        }

        return true;
    } else {
        /* If component not found on base, check if base itself inherits */
        ecs_type_t base_type = base_info.table->type;
        return override_component(world, component, base_type, data, column, 
            row, count);
    }
}

static
bool override_component(
    ecs_world_t * world,
    ecs_entity_t component,
    ecs_type_t type,
    ecs_data_t * data,
    ecs_column_t * column,
    int32_t row,
    int32_t count)
{
    ecs_entity_t *type_array = ecs_vector_first(type, ecs_entity_t);
    int32_t i, type_count = ecs_vector_count(type);

    /* Walk prefabs */
    i = type_count - 1;
    do {
        ecs_entity_t e = type_array[i];

        if (!(e & ECS_ROLE_MASK)) {
            break;
        }

        if (ECS_HAS_RELATION(e, EcsIsA)) {
            if (override_from_base(world, ecs_pair_object(world, e), component,
                data, column, row, count))
            {
                return true;
            }
        }
    } while (--i >= 0);

    return false;
}

static
void ecs_components_override(
    ecs_world_t * world,
    ecs_table_t * table,
    ecs_data_t * data,
    int32_t row,
    int32_t count,
    ecs_column_info_t * component_info,
    int32_t component_count,
    bool run_on_set)
{
    ecs_assert(data != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(component_count != 0, ECS_INTERNAL_ERROR, NULL);

    ecs_table_t *table_without_base = table;
    ecs_column_t *columns = data->columns;
    ecs_type_t type = table->type;
    int32_t column_count = table->column_count;

    int i;
    for (i = 0; i < component_count; i ++) {
        ecs_entity_t component = component_info[i].id;

        if (component >= ECS_HI_COMPONENT_ID) {
            if (ECS_HAS_RELATION(component, EcsIsA)) {
                ecs_entity_t base = ECS_PAIR_OBJECT(component);

                /* Illegal to create an instance of 0 */
                ecs_assert(base != 0, ECS_INVALID_PARAMETER, NULL);
                instantiate(world, base, table, data, row, count);

                /* If table has on_set systems, get table without the base
                 * entity that was just added. This is needed to determine the
                 * diff between the on_set systems of the current table and the
                 * table without the base, as these are the systems that need to
                 * be invoked */
                ecs_entities_t to_remove = {
                    .array = &component,
                    .count = 1
                };

                table_without_base = ecs_table_traverse_remove(world, 
                    table_without_base, &to_remove, NULL);
            }
        }

        int32_t column_index = component_info[i].column;
        if (column_index == -1 || column_index >= column_count) {
            continue;
        }

        /* column_index is lower than column count, which means we must have
         * data columns */
        ecs_assert(data->columns != NULL, ECS_INTERNAL_ERROR, NULL);

        if (!data->columns[column_index].size) {
            continue;
        }

        ecs_column_t *column = &columns[column_index];
        if (override_component(world, component, type, data, column, 
            row, count)) 
        {
            ecs_entities_t to_remove = {
                .array = &component,
                .count = 1
            };
            table_without_base = ecs_table_traverse_remove(world, 
                table_without_base, &to_remove, NULL);
        }
    }

    /* Run OnSet actions when a base entity is added to the entity for 
     * components not overridden by the entity. */
    if (run_on_set && table_without_base != table) {
        ecs_run_monitors(world, table, table->on_set_all, row, count, 
            table_without_base->on_set_all);
    }
}

static
void set_switch(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t * data,
    int32_t row,
    int32_t count,    
    ecs_entities_t *entities,
    bool reset)
{
    ecs_entity_t *array = entities->array;
    int32_t i, comp_count = entities->count;

    for (i = 0; i < comp_count; i ++) {
        ecs_entity_t e = array[i];

        if (ECS_HAS_ROLE(e, CASE)) {
            e = e & ECS_COMPONENT_MASK;

            ecs_entity_t sw_case = 0;
            if (!reset) {
                sw_case = e;
                ecs_assert(sw_case != 0, ECS_INTERNAL_ERROR, NULL);
            }

            int32_t sw_index = ecs_table_switch_from_case(world, table, e);
            ecs_assert(sw_index != -1, ECS_INTERNAL_ERROR, NULL);
            ecs_switch_t *sw = data->sw_columns[sw_index].data;
            ecs_assert(sw != NULL, ECS_INTERNAL_ERROR, NULL);
            
            int32_t r;
            for (r = 0; r < count; r ++) {
                ecs_switch_set(sw, row + r, sw_case);
            }
        }
    }
}

static
void ecs_components_switch(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data,
    int32_t row,
    int32_t count,
    ecs_entities_t *added,
    ecs_entities_t *removed)
{
    if (added) {
        set_switch(world, table, data, row, count, added, false);
    }
    if (removed) {
        set_switch(world, table, data, row, count, removed, true);
    } 
}

static
void notify(
    ecs_world_t * world,
    ecs_table_t * table,
    ecs_data_t * data,
    int32_t row,
    int32_t count,
    ecs_entity_t event,
    ecs_entities_t *ids)
{
    ecs_assert(data != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_id_t *arr = ids->array;
    int32_t arr_count = ids->count;

    int i;
    for (i = 0; i < arr_count; i ++) {
        ecs_triggers_notify(world, arr[i], event, table, data, row, count);
    }
}

void ecs_run_add_actions(
    ecs_world_t * world,
    ecs_table_t * table,
    ecs_data_t * data,
    int32_t row,
    int32_t count,
    ecs_entities_t * added,
    bool get_all,
    bool run_on_set)
{
    ecs_assert(added != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(added->count < ECS_MAX_ADD_REMOVE, ECS_INVALID_PARAMETER, NULL);

    ecs_column_info_t cinfo[ECS_MAX_ADD_REMOVE];
    ecs_get_column_info(world, table, added, cinfo, get_all);
    int added_count = added->count;

    if (table->flags & EcsTableHasBase) {
        ecs_components_override(
            world, table, data, row, count, cinfo, 
            added_count, run_on_set);
    }

    if (table->flags & EcsTableHasSwitch) {
        ecs_components_switch(world, table, data, row, count, added, NULL);
    }

    if (table->flags & EcsTableHasOnAdd) {
        notify(world, table, data, row, count, EcsOnAdd, added);
    }
}

void ecs_run_remove_actions(
    ecs_world_t * world,
    ecs_table_t * table,
    ecs_data_t * data,
    int32_t row,
    int32_t count,
    ecs_entities_t * removed)
{
    ecs_assert(removed != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(removed->count < ECS_MAX_ADD_REMOVE, ECS_INVALID_PARAMETER, NULL);

    if (table->flags & EcsTableHasOnRemove) {
        notify(world, table, data, row, count, EcsOnRemove, removed);
    }   
}

static
int32_t new_entity(
    ecs_world_t * world,
    ecs_entity_t entity,
    ecs_entity_info_t * info,
    ecs_table_t * new_table,
    ecs_entities_t * added)
{
    ecs_record_t *record = info->record;
    ecs_data_t *new_data = ecs_table_get_or_create_data(new_table);
    int32_t new_row;

    ecs_assert(added != NULL, ECS_INTERNAL_ERROR, NULL);

    if (!record) {
        record = ecs_eis_ensure(world, entity);
    }

    new_row = ecs_table_append(
        world, new_table, new_data, entity, record, true);

    record->table = new_table;
    record->row = ecs_row_to_record(new_row, info->is_watched);

    ecs_assert(
        ecs_vector_count(new_data[0].entities) > new_row, 
        ECS_INTERNAL_ERROR, NULL);

    if (new_table->flags & EcsTableHasAddActions) {
        ecs_run_add_actions(
            world, new_table, new_data, new_row, 1, added, true, true);

        if (new_table->flags & EcsTableHasMonitors) {
            ecs_run_monitors(
                world, new_table, new_table->monitors, new_row, 1, NULL);              
        }        
    }

    info->data = new_data;
    
    return new_row;
}

static
int32_t move_entity(
    ecs_world_t * world,
    ecs_entity_t entity,
    ecs_entity_info_t * info,
    ecs_table_t * src_table,
    ecs_data_t * src_data,
    int32_t src_row,
    ecs_table_t * dst_table,
    ecs_entities_t * added,
    ecs_entities_t * removed)
{    
    ecs_data_t *dst_data = ecs_table_get_or_create_data(dst_table);
    ecs_assert(src_data != dst_data, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(ecs_is_alive(world, entity), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(src_table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(src_data != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(src_row >= 0, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(ecs_vector_count(src_data->entities) > src_row, 
        ECS_INTERNAL_ERROR, NULL);

    ecs_record_t *record = info->record;
    ecs_assert(!record || record == ecs_eis_get(world, entity), 
        ECS_INTERNAL_ERROR, NULL);

    int32_t dst_row = ecs_table_append(world, dst_table, dst_data, entity, 
        record, false);

    record->table = dst_table;
    record->row = ecs_row_to_record(dst_row, info->is_watched);

    ecs_assert(ecs_vector_count(src_data->entities) > src_row, 
        ECS_INTERNAL_ERROR, NULL);

    /* Copy entity & components from src_table to dst_table */
    if (src_table->type) {
        /* If components were removed, invoke remove actions before deleting */
        if (removed && (src_table->flags & EcsTableHasRemoveActions)) {
            /* If entity was moved, invoke UnSet monitors for each component that
             * the entity no longer has */
            ecs_run_monitors(world, dst_table, src_table->un_set_all, 
                src_row, 1, dst_table->un_set_all);

            ecs_run_remove_actions(
                world, src_table, src_data, src_row, 1, removed);
        }

        ecs_table_move(world, entity, entity, dst_table, dst_data, dst_row, 
            src_table, src_data, src_row);                
    }
    
    ecs_table_delete(world, src_table, src_data, src_row, false);

    /* If components were added, invoke add actions */
    if (src_table != dst_table || (added && added->count)) {
        if (added && (dst_table->flags & EcsTableHasAddActions)) {
            ecs_run_add_actions(
                world, dst_table, dst_data, dst_row, 1, added, false, true);
        }

        /* Run monitors */
        if (dst_table->flags & EcsTableHasMonitors) {
            ecs_run_monitors(world, dst_table, dst_table->monitors, dst_row, 
                1, src_table->monitors);
        }

        /* If removed components were overrides, run OnSet systems for those, as 
         * the value of those components changed from the removed component to 
         * the value of component on the base entity */
        if (removed && dst_table->flags & EcsTableHasBase) {
            ecs_run_monitors(world, dst_table, src_table->on_set_override, 
                dst_row, 1, dst_table->on_set_override);          
        }
    }

    info->data = dst_data;

    return dst_row;
}

static
void delete_entity(
    ecs_world_t * world,
    ecs_table_t * src_table,
    ecs_data_t * src_data,
    int32_t src_row,
    ecs_entities_t * removed)
{
    if (removed) {
        ecs_run_monitors(world, src_table, src_table->un_set_all, 
            src_row, 1, NULL);

        /* Invoke remove actions before deleting */
        if (src_table->flags & EcsTableHasRemoveActions) {   
            ecs_run_remove_actions(
                world, src_table, src_data, src_row, 1, removed);
        } 
    }

    ecs_table_delete(world, src_table, src_data, src_row, true);
}

/* Updating component monitors is a relatively expensive operation that only
 * happens for entities that are monitored. The approach balances the amount of
 * processing between the operation on the entity vs the amount of work that
 * needs to be done to rematch queries, as a simple brute force approach does
 * not scale when there are many tables / queries. Therefore we need to do a bit
 * of bookkeeping that is more intelligent than simply flipping a flag */
static
void update_component_monitor_w_array(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_entity_t relation,
    ecs_entities_t * entities)
{
    if (!entities) {
        return;
    }

    int i;
    for (i = 0; i < entities->count; i ++) {
        ecs_entity_t id = entities->array[i];
        if (ECS_HAS_ROLE(id, PAIR)) {
            ecs_entity_t rel = ECS_PAIR_RELATION(id);
            
            /* If a relationship has changed, check if it could have impacted
             * the shape of the graph for that relationship. If so, mark the
             * relationship as dirty */        
            if (rel != relation && ecs_get_id_record(world, ecs_pair(rel, entity))) {
                update_component_monitor_w_array(world, entity, rel, entities);
            }

        }
        
        if (ECS_HAS_RELATION(id, EcsIsA)) {
            /* If an IsA relationship is added to a monitored entity (can
             * be either a parent or a base) component monitors need to be
             * evaluated for the components of the prefab. */
            ecs_entity_t base = ecs_pair_object(world, id);
            ecs_type_t type = ecs_get_type(world, base);
            ecs_entities_t base_entities = ecs_type_to_entities(type);

            /* This evaluates the component monitor for all components of the
             * base entity. If the base entity contains IsA relationships
             * these will be evaluated recursively as well. */
            update_component_monitor_w_array(
                world, entity, relation, &base_entities);               
        } else {
            ecs_monitor_mark_dirty(world, relation, id);
        }
    }
}

static
void update_component_monitors(
    ecs_world_t * world,
    ecs_entity_t entity,
    ecs_entities_t * added,
    ecs_entities_t * removed)
{
    update_component_monitor_w_array(world, entity, 0, added);
    update_component_monitor_w_array(world, entity, 0, removed);
}

static
void commit(
    ecs_world_t * world,
    ecs_entity_t entity,
    ecs_entity_info_t * info,
    ecs_table_t * dst_table,   
    ecs_entities_t * added,
    ecs_entities_t * removed)
{
    ecs_assert(!world->is_readonly, ECS_INTERNAL_ERROR, NULL);
    
    ecs_table_t *src_table = info->table;
    if (src_table == dst_table) {
        /* If source and destination table are the same no action is needed *
         * However, if a component was added in the process of traversing a
         * table, this suggests that a case switch could have occured. */
        if (((added && added->count) || (removed && removed->count)) && 
             src_table && src_table->flags & EcsTableHasSwitch) 
        {
            ecs_components_switch(
                world, src_table, info->data, info->row, 1, added, removed);
        }

        return;
    }  

    if (src_table) {
        ecs_data_t *src_data = info->data;
        ecs_assert(dst_table != NULL, ECS_INTERNAL_ERROR, NULL);

        if (dst_table->type) { 
            info->row = move_entity(world, entity, info, src_table, 
                src_data, info->row, dst_table, added, removed);
            info->table = dst_table;
        } else {
            delete_entity(
                world, src_table, src_data, info->row, 
                removed);

            ecs_eis_set(world, entity, &(ecs_record_t){
                NULL, (info->is_watched == true) * -1
            });
        }      
    } else {        
        if (dst_table->type) {
            info->row = new_entity(world, entity, info, dst_table, added);
            info->table = dst_table;
        }        
    }

    /* If the entity is being watched, it is being monitored for changes and
    * requires rematching systems when components are added or removed. This
    * ensures that systems that rely on components from containers or prefabs
    * update the matched tables when the application adds or removes a 
    * component from, for example, a container. */
    if (info->is_watched) {
        update_component_monitors(world, entity, added, removed);
    }

    if ((!src_table || !src_table->type) && world->range_check_enabled) {
        ecs_assert(!world->stats.max_id || entity <= world->stats.max_id, ECS_OUT_OF_RANGE, 0);
        ecs_assert(entity >= world->stats.min_id, ECS_OUT_OF_RANGE, 0);
    } 
}

static
void* get_base_component(
    const ecs_world_t * world,
    ecs_entity_info_t * info,
    ecs_entity_t component)
{
    ecs_type_t type = info->table->type;
    ecs_entity_t *type_buffer = ecs_vector_first(type, ecs_entity_t);
    int32_t p = -1;
    void *ptr = NULL;

    while (!ptr && (p = find_prefab(type, p)) != -1) {
        ecs_entity_t prefab = ecs_pair_object(world, type_buffer[p]);
        ecs_entity_info_t prefab_info;
        if (ecs_get_info(world, prefab, &prefab_info) && prefab_info.table) {
            ptr = get_component(&prefab_info, component);
            if (!ptr) {
                ptr = get_base_component(
                    world, &prefab_info, component);
            }
        }
    }

    return ptr;
}

static
void new(
    ecs_world_t * world,
    ecs_entity_t entity,
    ecs_entities_t * to_add)
{
    ecs_entity_info_t info = {0};
    ecs_table_t *table = ecs_table_traverse_add(
        world, world->stage.scope_table, to_add, NULL);
    new_entity(world, entity, &info, table, to_add);
}

static
const ecs_entity_t* new_w_data(
    ecs_world_t * world,
    ecs_table_t * table,
    ecs_entities_t * component_ids,
    int32_t count,
    void ** component_data,
    int32_t * row_out)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(count != 0, ECS_INTERNAL_ERROR, NULL);
    
    int32_t sparse_count = ecs_eis_count(world);
    const ecs_entity_t *ids = ecs_sparse_new_ids(world->store.entity_index, count);
    ecs_assert(ids != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_type_t type = table->type;   

    if (!type) {
        return ids;        
    }

    ecs_entities_t component_array = { 0 };
    if (!component_ids) {
        component_ids = &component_array;
        component_array.array = ecs_vector_first(type, ecs_entity_t);
        component_array.count = ecs_vector_count(type);
    }

    ecs_data_t *data = ecs_table_get_or_create_data(table);
    int32_t row = ecs_table_appendn(world, table, data, count, ids);
    ecs_entities_t added = ecs_type_to_entities(type);
    
    /* Update entity index. */
    int i;
    ecs_record_t **record_ptrs = ecs_vector_first(data->record_ptrs, ecs_record_t*);
    for (i = 0; i < count; i ++) { 
        record_ptrs[row + i] = ecs_eis_set(world, ids[i], 
        &(ecs_record_t){
            .table = table,
            .row = row + i + 1
        });
    }

    ecs_defer_none(world, &world->stage);

    ecs_run_add_actions(world, table, data, row, count, &added, 
        true, component_data == NULL);

    if (component_data) {
        /* Set components that we're setting in the component mask so the init
         * actions won't call OnSet triggers for them. This ensures we won't
         * call OnSet triggers multiple times for the same component */
        int32_t c_i;
        for (c_i = 0; c_i < component_ids->count; c_i ++) {
            ecs_entity_t c = component_ids->array[c_i];
            
            /* Bulk copy column data into new table */
            int32_t table_index = ecs_type_index_of(type, c);
            ecs_assert(table_index >= 0, ECS_INTERNAL_ERROR, NULL);
            if (table_index >= table->column_count) {
                continue;
            }

            ecs_column_t *column = &data->columns[table_index];
            int16_t size = column->size;
            int16_t alignment = column->alignment;
            void *ptr = ecs_vector_first_t(column->data, size, alignment);
            ptr = ECS_OFFSET(ptr, size * row);

            /* Copy component data */
            void *src_ptr = component_data[c_i];
            if (!src_ptr) {
                continue;
            }

            const ecs_type_info_t *cdata = get_c_info(world, c);
            ecs_copy_t copy;
            if (cdata && (copy = cdata->lifecycle.copy)) {
                ecs_entity_t *entities = ecs_vector_first(data->entities, ecs_entity_t);
                copy(world, c, entities, entities, ptr, src_ptr, 
                    ecs_to_size_t(size), count, cdata->lifecycle.ctx);
            } else {
                ecs_os_memcpy(ptr, src_ptr, size * count);
            }
        };

        ecs_run_set_systems(world, &added, table, data, row, count, true);        
    }

    ecs_run_monitors(world, table, table->monitors, row, count, NULL);

    ecs_defer_flush(world, &world->stage);

    if (row_out) {
        *row_out = row;
    }

    ids = ecs_sparse_ids(world->store.entity_index);

    return &ids[sparse_count];
}

static
bool has_type(
    const ecs_world_t *world,
    ecs_entity_t entity,
    ecs_type_t type,
    bool match_any,
    bool match_prefabs)    
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);

    if (!entity) {
        return false;
    }

    if (!type) {
        return true;
    }

    ecs_type_t entity_type = ecs_get_type(world, entity);

    return ecs_type_contains(
        world, entity_type, type, match_any, match_prefabs) != 0;
}

static
void add_remove(
    ecs_world_t * world,
    ecs_entity_t entity,
    ecs_entities_t * to_add,
    ecs_entities_t * to_remove)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(to_add->count < ECS_MAX_ADD_REMOVE, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(to_remove->count < ECS_MAX_ADD_REMOVE, ECS_INVALID_PARAMETER, NULL);

    ecs_entity_info_t info;
    ecs_get_info(world, entity, &info);

    ecs_entity_t add_buffer[ECS_MAX_ADD_REMOVE];
    ecs_entity_t remove_buffer[ECS_MAX_ADD_REMOVE];
    ecs_entities_t added = { .array = add_buffer };
    ecs_entities_t removed = { .array = remove_buffer };

    ecs_table_t *src_table = info.table;

    ecs_table_t *dst_table = ecs_table_traverse_remove(
        world, src_table, to_remove, &removed);

    dst_table = ecs_table_traverse_add(
        world, dst_table, to_add, &added);    

    commit(world, entity, &info, dst_table, &added, &removed);
}

static
void add_entities_w_info(
    ecs_world_t * world,
    ecs_entity_t entity,
    ecs_entity_info_t * info,
    ecs_entities_t * components)
{
    ecs_assert(components->count < ECS_MAX_ADD_REMOVE, ECS_INVALID_PARAMETER, NULL);
    ecs_entity_t buffer[ECS_MAX_ADD_REMOVE];
    ecs_entities_t added = { .array = buffer };

    ecs_table_t *src_table = info->table;
    ecs_table_t *dst_table = ecs_table_traverse_add(
        world, src_table, components, &added);

    commit(world, entity, info, dst_table, &added, NULL);
}

static
void remove_entities_w_info(
    ecs_world_t * world,
    ecs_entity_t entity,
    ecs_entity_info_t * info,
    ecs_entities_t * components)
{
    ecs_assert(components->count < ECS_MAX_ADD_REMOVE, ECS_INVALID_PARAMETER, NULL);
    ecs_entity_t buffer[ECS_MAX_ADD_REMOVE];
    ecs_entities_t removed = { .array = buffer };

    ecs_table_t *src_table = info->table;
    ecs_table_t *dst_table = ecs_table_traverse_remove(
        world, src_table, components, &removed);

    commit(world, entity, info, dst_table, NULL, &removed);
}

static
void add_entities(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_entities_t * components)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(components->count < ECS_MAX_ADD_REMOVE, ECS_INVALID_PARAMETER, NULL);
    ecs_stage_t *stage = ecs_stage_from_world(&world);

    if (ecs_defer_add(world, stage, entity, components)) {
        return;
    }

    ecs_entity_info_t info;
    ecs_get_info(world, entity, &info);

    ecs_entity_t buffer[ECS_MAX_ADD_REMOVE];
    ecs_entities_t added = { .array = buffer };

    ecs_table_t *src_table = info.table;
    ecs_table_t *dst_table = ecs_table_traverse_add(
        world, src_table, components, &added);

    commit(world, entity, &info, dst_table, &added, NULL);

    ecs_defer_flush(world, stage);
}

static
void remove_entities(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_entities_t * components)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(components->count < ECS_MAX_ADD_REMOVE, ECS_INVALID_PARAMETER, NULL);    
    ecs_stage_t *stage = ecs_stage_from_world(&world);

    if (ecs_defer_remove(world, stage, entity, components)) {
        return;
    }

    ecs_entity_info_t info;
    ecs_get_info(world, entity, &info);

    ecs_entity_t buffer[ECS_MAX_ADD_REMOVE];
    ecs_entities_t removed = { .array = buffer };

    ecs_table_t *src_table = info.table;
    ecs_table_t *dst_table = ecs_table_traverse_remove(
        world, src_table, components, &removed);

    commit(world, entity, &info, dst_table, NULL, &removed);

    ecs_defer_flush(world, stage);
}

static
void *get_mutable(
    ecs_world_t * world,
    ecs_entity_t entity,
    ecs_entity_t component,
    ecs_entity_info_t * info,
    bool * is_added)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(component != 0, ECS_INVALID_PARAMETER, NULL);
    ecs_assert((component & ECS_COMPONENT_MASK) == component || ECS_HAS_ROLE(component, PAIR), ECS_INVALID_PARAMETER, NULL);

    void *dst = NULL;
    if (ecs_get_info(world, entity, info) && info->table) {
        dst = get_component(info, component);
    }

    ecs_table_t *table = info->table;

    if (!dst) {
        ecs_entities_t to_add = {
            .array = &component,
            .count = 1
        };

        add_entities_w_info(world, entity, info, &to_add);

        ecs_get_info(world, entity, info);
        ecs_assert(info->table != NULL, ECS_INTERNAL_ERROR, NULL);

        dst = get_component(info, component);

        if (is_added) {
            *is_added = table != info->table;
        }

        return dst;
    } else {
        if (is_added) {
            *is_added = false;
        }

        return dst;
    }
}

/* -- Private functions -- */

int32_t ecs_record_to_row(
    int32_t row, 
    bool *is_watched_out) 
{
    bool is_watched = row < 0;
    row = row * -(is_watched * 2 - 1) - 1 * (row != 0);
    *is_watched_out = is_watched;
    return row;
}

int32_t ecs_row_to_record(
    int32_t row, 
    bool is_watched) 
{
    return (row + 1) * -(is_watched * 2 - 1);
}

ecs_entities_t ecs_type_to_entities(
    ecs_type_t type)
{
    return (ecs_entities_t){
        .array = ecs_vector_first(type, ecs_entity_t),
        .count = ecs_vector_count(type)
    };
}

void ecs_set_watch(
    ecs_world_t *world,
    ecs_entity_t entity)
{    
    (void)world;

    ecs_record_t *record = ecs_eis_get(world, entity);
    if (!record) {
        ecs_record_t new_record = {.row = -1, .table = NULL};
        ecs_eis_set(world, entity, &new_record);
    } else {
        if (record->row > 0) {
            record->row *= -1;

        } else if (record->row == 0) {
            /* If entity is empty, there is no index to change the sign of. In
             * this case, set the index to -1, and assign an empty type. */
            record->row = -1;
            record->table = NULL;
        }
    }
}

ecs_entity_t ecs_find_in_type(
    const ecs_world_t *world,
    ecs_type_t type,
    ecs_entity_t component,
    ecs_entity_t flags)
{
    ecs_vector_each(type, ecs_entity_t, c_ptr, {
        ecs_entity_t c = *c_ptr;

        if (!ECS_HAS_RELATION(c, flags)) {
            continue;
        }

        ecs_entity_t e = ecs_pair_object(world, c);

        if (component) {
            ecs_type_t component_type = ecs_get_type(world, e);
            if (!ecs_type_has_id(world, component_type, component)) {
                continue;
            }
        }

        return e;
    });

    return 0;
}


/* -- Public functions -- */

ecs_entity_t ecs_new_id(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);

    const ecs_stage_t *stage = ecs_stage_from_readonly_world(world);

    /* It is possible that the world passed to this function is a stage, so
     * make sure we have the actual world. Cast away const since this is one of
     * the few functions that may modify the world while it is in readonly mode,
     * since it is thread safe (uses atomic inc when in threading mode) */
    ecs_world_t *unsafe_world = (ecs_world_t*)ecs_get_world(world);

    ecs_entity_t entity;

    int32_t stage_count = ecs_get_stage_count(unsafe_world);
    if (stage->asynchronous || (ecs_os_has_threading() && stage_count > 1)) {
        /* Can't atomically increase number above max int */
        ecs_assert(
            unsafe_world->stats.last_id < UINT_MAX, ECS_INTERNAL_ERROR, NULL);

        entity = (ecs_entity_t)ecs_os_ainc(
            (int32_t*)&unsafe_world->stats.last_id);
    } else {
        entity = ecs_eis_recycle(unsafe_world);
    }

    ecs_assert(!unsafe_world->stats.max_id || 
        entity <= unsafe_world->stats.max_id, 
        ECS_OUT_OF_RANGE, NULL);

    return entity;
}

ecs_entity_t ecs_new_component_id(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);

    /* It is possible that the world passed to this function is a stage, so
     * make sure we have the actual world. Cast away const since this is one of
     * the few functions that may modify the world while it is in readonly mode,
     * but only if single threaded. */
    ecs_world_t *unsafe_world = (ecs_world_t*)ecs_get_world(world);

    if (unsafe_world->is_readonly) {
        /* Can't issue new comp id while iterating when in multithreaded mode */
        ecs_assert(ecs_get_stage_count(world) <= 1, 
            ECS_INVALID_WHILE_ITERATING, NULL);
    }

    ecs_entity_t id;

    if (unsafe_world->stats.last_component_id < ECS_HI_COMPONENT_ID) {
        do {
            id = unsafe_world->stats.last_component_id ++;
        } while (ecs_exists(unsafe_world, id) && id < ECS_HI_COMPONENT_ID);        
    }
    
    if (unsafe_world->stats.last_component_id >= ECS_HI_COMPONENT_ID) {
        /* If the low component ids are depleted, return a regular entity id */
        id = ecs_new_id(unsafe_world);
    }

    /* Add scope to component */
    ecs_entity_t scope = unsafe_world->stage.scope;
    if (scope) {
        ecs_add_pair(world, id, EcsChildOf, scope);
    }    

    return id;
}

ecs_entity_t ecs_new_w_type(
    ecs_world_t *world,
    ecs_type_t type)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);

    ecs_stage_t *stage = ecs_stage_from_world(&world);    
    ecs_entity_t entity = ecs_new_id(world);

    ecs_entities_t to_add = ecs_type_to_entities(type);
    if (ecs_defer_new(world, stage, entity, &to_add)) {
        return entity;
    }

    if (type || world->stage.scope) {
        new(world, entity, &to_add);
    } else {
        ecs_eis_set(world, entity, &(ecs_record_t){ 0 });
    }

    ecs_defer_flush(world, stage);    

    return entity;
}

ecs_entity_t ecs_new_w_id(
    ecs_world_t *world,
    ecs_id_t id)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);

    ecs_stage_t *stage = ecs_stage_from_world(&world);    
    ecs_entity_t entity = ecs_new_id(world);

    ecs_entities_t to_add = {
        .array = &id,
        .count = 1
    };

    if (ecs_defer_new(world, stage, entity, &to_add)) {
        return entity;
    } 

    if (id || stage->scope) {
        ecs_entity_t old_scope = 0;
        if (ECS_HAS_RELATION(id, EcsChildOf)) {
            old_scope = ecs_set_scope(world, 0);
        }

        new(world, entity, &to_add);

        if (ECS_HAS_RELATION(id, EcsChildOf)) {
            ecs_set_scope(world, old_scope);
        }
    } else {
        ecs_eis_set(world, entity, &(ecs_record_t){ 0 });
    }

    ecs_defer_flush(world, stage);

    return entity;
}

#ifdef FLECS_PARSER
static
ecs_table_t *traverse_from_expr(
    ecs_world_t *world,
    ecs_table_t *table,
    const char *name,
    const char *expr,
    ecs_entities_t *modified,
    bool is_add,
    bool replace_and)
{
    const char *ptr = expr;
    if (ptr) {
        ecs_term_t term = {0};
        while (ptr[0] && (ptr = ecs_parse_term(world, name, expr, ptr, &term))) {
            if (!ecs_term_is_set(&term)) {
                break;
            }

            if (ecs_term_finalize(world, name, expr, &term)) {
                return NULL;
            }

            if (!ecs_term_is_trivial(&term)) {
                ecs_parser_error(name, expr, (ptr - expr), 
                    "invalid non-trivial term in add expression");
                return NULL;
            }

            if (term.oper == EcsAnd || !replace_and) {
                /* Regular AND expression */
                ecs_entities_t arr = { .array = &term.id, .count = 1 };
                if (is_add) {
                    table = ecs_table_traverse_add(world, table, &arr, modified);
                } else {
                    table = ecs_table_traverse_remove(world, table, &arr, modified);
                }

                ecs_assert(table != NULL, ECS_INVALID_PARAMETER, NULL);
            } else if (term.oper == EcsAndFrom) {
                /* Add all components from the specified type */
                const EcsType *t = ecs_get(world, term.id, EcsType);
                if (!t) {
                    ecs_parser_error(name, expr, (ptr - expr), 
                        "expected type for AND role");
                    return NULL;
                }
                
                ecs_id_t *ids = ecs_vector_first(t->normalized, ecs_id_t);
                int32_t i, count = ecs_vector_count(t->normalized);
                for (i = 0; i < count; i ++) {
                    ecs_entities_t arr = { .array = &ids[i], .count = 1 };
                    if (is_add) {
                        table = ecs_table_traverse_add(
                            world, table, &arr, modified);
                    } else {
                        table = ecs_table_traverse_remove(
                            world, table, &arr, modified);
                    }
                    
                    ecs_assert(table != NULL, ECS_INVALID_PARAMETER, NULL);
                }
            }

            ecs_term_fini(&term);
        }
    }

    return table;
}
#endif

ecs_entity_t ecs_entity_init(
    ecs_world_t *world,
    const ecs_entity_desc_t *desc)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(desc != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_entity_t scope = ecs_get_scope(world);

    const char *name = desc->name;
    const char *sep = desc->sep;
    if (!sep) {
        sep = ".";
    }

    bool new_entity = false;
    bool name_assigned = false;

    /* Remove optional prefix from name. Entity names can be derived from 
     * language identifiers, such as components (typenames) and systems
     * function names). Because C does not have namespaces, such identifiers
     * often encode the namespace as a prefix.
     * To ensure interoperability between C and C++ (and potentially other 
     * languages with namespacing) the entity must be stored without this prefix
     * and with the proper namespace, which is what the name_prefix is for */
    const char *prefix = world->name_prefix;
    if (name && prefix) {
        ecs_size_t len = ecs_os_strlen(prefix);
        if (!ecs_os_strncmp(name, prefix, len) && 
           (isupper(name[len]) || name[len] == '_')) 
        {
            if (name[len] == '_') {
                name = name + len + 1;
            } else {
                name = name + len;
            }
        }
    }

    /* Find or create entity */
    ecs_entity_t result = desc->entity;
    if (!result) {
        if (name) {
            result = ecs_lookup_path_w_sep(world, 0, name, sep, NULL, false);
            if (result) {
                name_assigned = true;
            }
        }

        if (!result) {
            if (desc->use_low_id) {
                result = ecs_new_component_id(world);
            } else {
                result = ecs_new_id(world);
            }
            new_entity = true;
        }
    } else {
        ecs_assert(ecs_is_valid(world, result), ECS_INVALID_PARAMETER, NULL);

        name_assigned = ecs_has(world, result, EcsName);
        if (name && name_assigned) {
            /* If entity has name, verify that name matches */
            char *path = ecs_get_path_w_sep(world, scope, result, 0, sep, NULL);
            if (path) {
                if (ecs_os_strcmp(path, name)) {
                    /* Mismatching name */
                    ecs_os_free(path);
                    return 0;
                }
                ecs_os_free(path);
            }
        }
    }

    /* Find existing table */
    ecs_entity_info_t info = {0};
    ecs_table_t *src_table = NULL, *table = NULL;
    if (!new_entity) {
        if (ecs_get_info(world, result, &info)) {
            table = info.table;
        }
    }

    ecs_entity_t added_buffer[ECS_MAX_ADD_REMOVE];
    ecs_entities_t added = { .array = added_buffer };

    ecs_entity_t removed_buffer[ECS_MAX_ADD_REMOVE];
    ecs_entities_t removed = { .array = removed_buffer };

    /* Find destination table */

    /* If this is a new entity without a name, add the scope. If a name is
     * provided, the scope will be added by the add_path_w_sep function */
    if (new_entity && scope && !name && !name_assigned) {
        ecs_entity_t id = ecs_pair(EcsChildOf, scope);
        ecs_entities_t arr = { .array = &id, .count = 1 };
        table = ecs_table_traverse_add(world, table, &arr, &added);
        ecs_assert(table != NULL, ECS_INVALID_PARAMETER, NULL);
    }

    /* If a name is provided but not yet assigned, add the Name component */
    if (name && !name_assigned) {
        ecs_entity_t id = ecs_id(EcsName);
        ecs_entities_t arr = { .array = &id, .count = 1 };
        table = ecs_table_traverse_add(world, table, &arr, &added);
        ecs_assert(table != NULL, ECS_INVALID_PARAMETER, NULL);            
    }

    /* Add components from the 'add' id array */
    int32_t i = 0;
    ecs_id_t id;
    const ecs_id_t *ids = desc->add;
    while ((i < ECS_MAX_ADD_REMOVE) && (id = ids[i ++])) {
        ecs_entities_t arr = { .array = &id, .count = 1 };
        table = ecs_table_traverse_add(world, table, &arr, &added);
        ecs_assert(table != NULL, ECS_INVALID_PARAMETER, NULL);
    }

    /* Add components from the 'remove' id array */
    i = 0;
    ids = desc->remove;
    while ((i < ECS_MAX_ADD_REMOVE) && (id = ids[i])) {
        ecs_entities_t arr = { .array = &id, .count = 1 };
        table = ecs_table_traverse_remove(world, table, &arr, &removed);
        ecs_assert(table != NULL, ECS_INVALID_PARAMETER, NULL);
        i ++;
    }

    /* Add components from the 'add_expr' expression */
    if (desc->add_expr) {
#ifdef FLECS_PARSER
        table = traverse_from_expr(
            world, table, name, desc->add_expr, &added, true, true);
#else
        ecs_abort(ECS_UNSUPPORTED, "parser addon is not available");
#endif
    }

    /* Remove components from the 'remove_expr' expression */
    if (desc->remove_expr) {
#ifdef FLECS_PARSER
    table = traverse_from_expr(
        world, table, name, desc->remove_expr, &removed, false, true);
#else
        ecs_abort(ECS_UNSUPPORTED, "parser addon is not available");
#endif
    }

    /* Commit entity to destination table */
    if (src_table != table) {
        commit(world, result, &info, table, &added, &removed);
    }

    /* Set name */
    if (name && !name_assigned) {
        ecs_add_path_w_sep(world, result, scope, name, sep, NULL);   
        if (desc->symbol) {
            EcsName *name_ptr = ecs_get_mut(world, result, EcsName, NULL);
            ecs_os_free(name_ptr->symbol);
            name_ptr->symbol = ecs_os_strdup(desc->symbol);
        }
    }

    return result;
}

ecs_entity_t ecs_component_init(
    ecs_world_t *world,
    const ecs_component_desc_t *desc)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_stage_from_world(&world);

    bool is_readonly = world->is_readonly;

    /* If world is in progress component may be registered, but only when not
     * in multithreading mode. */
    if (is_readonly) {
        ecs_assert(ecs_get_stage_count(world) <= 1, 
            ECS_INVALID_WHILE_ITERATING, NULL);

        /* Component creation should not be deferred */
        world->is_readonly = false;
    }

    ecs_entity_desc_t entity_desc = desc->entity;
    entity_desc.use_low_id = true;
    if (!entity_desc.symbol) {
        entity_desc.symbol = entity_desc.name;
    }

    ecs_entity_t e = desc->entity.entity;
    ecs_entity_t result = ecs_entity_init(world, &entity_desc);
    if (!result) {
        return 0;
    }

    bool added = false;
    EcsComponent *ptr = ecs_get_mut(world, result, EcsComponent, &added);

    if (added) {
        ptr->size = ecs_from_size_t(desc->size);
        ptr->alignment = ecs_from_size_t(desc->alignment);
    } else {
        if (ptr->size != ecs_from_size_t(desc->size)) {
            ecs_abort(ECS_INVALID_COMPONENT_SIZE, desc->entity.name);
        }
        if (ptr->alignment != ecs_from_size_t(desc->alignment)) {
            ecs_abort(ECS_INVALID_COMPONENT_SIZE, desc->entity.name);
        }
    }

    ecs_modified(world, result, EcsComponent);

    if (e > world->stats.last_component_id && e < ECS_HI_COMPONENT_ID) {
        world->stats.last_component_id = e + 1;
    }

    /* Ensure components cannot be deleted */
    ecs_add_pair(world, result, EcsOnDelete, EcsThrow);    

    if (is_readonly) {
        world->is_readonly = true;
    }

    ecs_assert(result != 0, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(ecs_has(world, result, EcsComponent), ECS_INTERNAL_ERROR, NULL);

    return result;
}

ecs_entity_t ecs_type_init(
    ecs_world_t *world,
    const ecs_type_desc_t *desc)
{
    ecs_entity_t result = ecs_entity_init(world, &desc->entity);
    if (!result) {
        return 0;
    }

    ecs_table_t *table = NULL, *normalized = NULL;

    ecs_entity_t added_buffer[ECS_MAX_ADD_REMOVE];
    ecs_entities_t added = { .array = added_buffer };

    /* Find destination table (and type) */

    /* Add components from the 'add' id array */
    int32_t i = 0;
    ecs_id_t id;
    const ecs_id_t *ids = desc->ids;
    while ((i < ECS_MAX_ADD_REMOVE) && (id = ids[i ++])) {
        ecs_entities_t arr = { .array = &id, .count = 1 };
        normalized = ecs_table_traverse_add(world, normalized, &arr, &added);
        table = ecs_table_traverse_add(world, table, &arr, &added);
        ecs_assert(table != NULL, ECS_INVALID_PARAMETER, NULL);
    }

    /* If expression is set, add it to the table */
    if (desc->ids_expr) {
#ifdef FLECS_PARSER
        normalized = traverse_from_expr(
            world, normalized, desc->entity.name, desc->ids_expr, &added, 
            true, true);

        table = traverse_from_expr(
            world, table, desc->entity.name, desc->ids_expr, &added, 
            true, false);
#else
        ecs_abort(ECS_UNSUPPORTED, "parser addon is not available");
#endif
    }

    ecs_type_t type = NULL;
    ecs_type_t normalized_type = NULL;
    
    if (table) {
        type = table->type;
    }
    if (normalized) {
        normalized_type = normalized->type;
    }

    bool add = false;
    EcsType *type_ptr = ecs_get_mut(world, result, EcsType, &add);
    if (add) {
        type_ptr->type = type;
        type_ptr->normalized = normalized_type;

        /* This will allow the type to show up in debug tools */
        if (type) {
            ecs_map_set(world->type_handles, (uintptr_t)type, &result);
        }

        ecs_modified(world, result, EcsType);
    } else {
        if (type_ptr->type != type) {
            ecs_abort(ECS_ALREADY_DEFINED, desc->entity.name);
        }
        if (type_ptr->normalized != normalized_type) {
            ecs_abort(ECS_ALREADY_DEFINED, desc->entity.name);
        }        
    }

    return result;
}

const ecs_entity_t* ecs_bulk_new_w_data(
    ecs_world_t *world,
    int32_t count,
    const ecs_entities_t *components,
    void * data)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);

    ecs_stage_t *stage = ecs_stage_from_world(&world);
    const ecs_entity_t *ids;
    if (ecs_defer_bulk_new(world, stage, count, components, data, &ids)) {
        return ids;
    }
    ecs_type_t type = ecs_type_find(world, components->array, components->count);
    ecs_table_t *table = ecs_table_from_type(world, type);    
    ids = new_w_data(world, table, NULL, count, data, NULL);
    ecs_defer_flush(world, stage);
    return ids;
}

const ecs_entity_t* ecs_bulk_new_w_type(
    ecs_world_t *world,
    ecs_type_t type,
    int32_t count)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);

    ecs_stage_t *stage = ecs_stage_from_world(&world);
    const ecs_entity_t *ids;
    ecs_entities_t components = ecs_type_to_entities(type);
    if (ecs_defer_bulk_new(world, stage, count, &components, NULL, &ids)) {
        return ids;
    }
    ecs_table_t *table = ecs_table_from_type(world, type);
    ids = new_w_data(world, table, NULL, count, NULL, NULL);
    ecs_defer_flush(world, stage);
    return ids;
}

const ecs_entity_t* ecs_bulk_new_w_id(
    ecs_world_t *world,
    ecs_id_t id,
    int32_t count)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, id), ECS_INVALID_PARAMETER, NULL);

    ecs_stage_t *stage = ecs_stage_from_world(&world);
    ecs_entities_t components = {
        .array = &id,
        .count = 1
    };
    const ecs_entity_t *ids;
    if (ecs_defer_bulk_new(world, stage, count, &components, NULL, &ids)) {
        return ids;
    }
    ecs_table_t *table = ecs_table_find_or_create(world, &components);
    ids = new_w_data(world, table, NULL, count, NULL, NULL);
    ecs_defer_flush(world, stage);
    return ids;
}

void ecs_clear(
    ecs_world_t *world,
    ecs_entity_t entity)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);

    ecs_stage_t *stage = ecs_stage_from_world(&world);
    if (ecs_defer_clear(world, stage, entity)) {
        return;
    }

    ecs_entity_info_t info;
    info.table = NULL;

    ecs_get_info(world, entity, &info);

    ecs_table_t *table = info.table;
    if (table) {
        ecs_type_t type = table->type;

        /* Remove all components */
        ecs_entities_t to_remove = ecs_type_to_entities(type);
        remove_entities_w_info(world, entity, &info, &to_remove);
    }    

    ecs_defer_flush(world, stage);
}

static
void on_delete_action(
    ecs_world_t *world,
    ecs_entity_t entity);

static
void throw_invalid_delete(
    ecs_world_t *world,
    ecs_id_t id)
{
    char buff[256];
    ecs_entity_str(world, id, buff, 256);
    ecs_abort(ECS_INVALID_DELETE, buff);    
}

static
void remove_from_table(
    ecs_world_t *world,
    ecs_table_t *src_table,
    ecs_id_t id,
    int32_t column)
{
    ecs_entity_t removed_buffer[ECS_MAX_ADD_REMOVE];
    ecs_entities_t removed = { .array = removed_buffer };    
    ecs_table_t *dst_table = src_table;
    bool is_pair = ECS_HAS_ROLE(id, PAIR);

    /* If id is pair, ensure dst_table has no instances of the relation */
    if (is_pair && ECS_PAIR_RELATION(id) != EcsWildcard) {
        int32_t i, count = ecs_vector_count(src_table->type);
        ecs_id_t *ids = ecs_vector_first(src_table->type, ecs_id_t);
        for (i = column; i < count; i ++) {
            ecs_id_t e = ids[i];
            if (ECS_PAIR_RELATION(id) != ECS_PAIR_RELATION(e)) {
                break;
            }

            ecs_entities_t to_remove = { .array = &e, .count = 1 };
            dst_table = ecs_table_traverse_remove(
                world, dst_table, &to_remove, &removed);
        }
    } else {
        /* If pair has a relationship wildcard, this removes a relationship for
         * a specific object. Get the relation + object to delete */
        if (is_pair) {
            ecs_id_t *ids = ecs_vector_first(src_table->type, ecs_id_t);
            id = ids[column];
        }
        ecs_entities_t to_remove = { .array = &id, .count = 1 };
        dst_table = ecs_table_traverse_remove(
            world, dst_table, &to_remove, &removed);
    }

    ecs_assert(dst_table != NULL, ECS_INTERNAL_ERROR, NULL);

    if (!dst_table->type) {
        /* If this removes all components, clear table */
        ecs_table_clear(world, src_table);
    } else {
        /* Otherwise, merge table into dst_table */
        if (dst_table != src_table) {
            ecs_data_t *src_data = ecs_table_get_data(src_table);
            int32_t src_count = ecs_table_count(src_table);
            if (removed.count && src_data) {
                ecs_run_remove_actions(world, src_table, 
                    src_data, 0, src_count, &removed);
            }

            ecs_data_t *dst_data = ecs_table_get_data(dst_table);
            dst_data = ecs_table_merge(
                world, dst_table, src_table, dst_data, src_data);
        }
    }
}

static
void delete_objects(
    ecs_world_t *world,
    ecs_table_t *table)
{
    ecs_data_t *data = ecs_table_get_data(table);
    if (data) {
        ecs_entity_t *entities = ecs_vector_first(
            data->entities, ecs_entity_t);

        int32_t i, count = ecs_vector_count(data->entities);
        for (i = 0; i < count; i ++) {
            ecs_entity_t e = entities[i];
            ecs_record_t *r = ecs_sparse_get_sparse(
                world->store.entity_index, ecs_record_t, e);
            
            /* If row is negative, it means the entity is being monitored. Only
             * monitored entities can have delete actions */
            if (r && r->row < 0) {
                /* Make row positive which prevents infinite recursion in case
                 * of cyclic delete actions */
                r->row = (-r->row) - 1;

                /* Run delete actions for objects */
                on_delete_action(world, entities[i]);
            }        
        }

        /* Clear components from table (invokes destructors, OnRemove) */
        ecs_table_delete_entities(world, table);            
    } 
}

static
void delete_tables_for_id_record(
    ecs_world_t *world,
    ecs_id_t id,
    ecs_id_record_t *idr)
{
    /* Delete tables in id record. Because deleting the table updates the
     * map, remove the map pointer from the id record. This will prevent the
     * table from removing itself from the map as it is deleted, which
     * allows for iterating the map without changing it. */
    ecs_map_t *table_index = idr->table_index;
    idr->table_index = NULL;
    ecs_map_iter_t it = ecs_map_iter(table_index);
    ecs_table_record_t *tr;
    while ((tr = ecs_map_next(&it, ecs_table_record_t, NULL))) {
        ecs_delete_table(world, tr->table);
    }
    ecs_map_free(table_index);

    ecs_clear_id_record(world, id);
}

static
void on_delete_object_action(
    ecs_world_t *world,
    ecs_id_t id)
{
    ecs_id_record_t *idr = ecs_get_id_record(world, id);
    if (idr) {
        ecs_map_t *table_index = idr->table_index;
        ecs_map_iter_t it = ecs_map_iter(table_index);
        ecs_table_record_t *tr;

        /* Execute the on delete action */
        while ((tr = ecs_map_next(&it, ecs_table_record_t, NULL))) {
            ecs_table_t *table = tr->table;
            if (!ecs_table_count(table)) {
                continue;
            }

            ecs_id_t *rel_id = ecs_vector_get(table->type, ecs_id_t, tr->column);
            ecs_assert(rel_id != NULL, ECS_INTERNAL_ERROR, NULL);

            ecs_entity_t rel = ECS_PAIR_RELATION(*rel_id);
            /* delete_object_action should be invoked for relations */
            ecs_assert(rel != 0, ECS_INTERNAL_ERROR,  NULL);

            /* Get the record for the relation, to find the delete action */
            ecs_id_record_t *idrr = ecs_get_id_record(world, rel);
            if (idrr) {
                ecs_entity_t action = idrr->on_delete_object;
                if (!action || action == EcsRemove) {
                    remove_from_table(world, table, id, tr->column);
                } else if (action == EcsDelete) {
                    delete_objects(world, table);
                } else if (action == EcsThrow) {
                    throw_invalid_delete(world, id);
                }
            } else {
                /* If no record was found for the relation, assume the default
                 * action which is to remove the relationship */
                remove_from_table(world, table, id, tr->column);
            }
        }

        delete_tables_for_id_record(world, id, idr);
    }
}

static
void on_delete_relation_action(
    ecs_world_t *world,
    ecs_id_t id)
{
    ecs_id_record_t *idr = ecs_get_id_record(world, id);
    if (idr) {
        ecs_entity_t on_delete = idr->on_delete;
        if (on_delete == EcsThrow) {
            throw_invalid_delete(world, id);
        }

        ecs_map_t *table_index = idr->table_index;
        ecs_map_iter_t it = ecs_map_iter(table_index);
        ecs_table_record_t *tr;
        while ((tr = ecs_map_next(&it, ecs_table_record_t, NULL))) {
            ecs_table_t *table = tr->table;
            ecs_entity_t action = idr->on_delete;
            if (!action || action == EcsRemove) {
                remove_from_table(world, table, id, tr->column);
            } else if (action == EcsDelete) {
                delete_objects(world, table);
            }
        }

        delete_tables_for_id_record(world, id, idr);
    }
}

static
void on_delete_action(
    ecs_world_t *world,
    ecs_entity_t entity)
{
    on_delete_relation_action(world, entity);
    on_delete_relation_action(world, ecs_pair(entity, EcsWildcard));
    on_delete_object_action(world, ecs_pair(EcsWildcard, entity));
}

void ecs_delete_children(
    ecs_world_t *world,
    ecs_entity_t parent)
{
    on_delete_action(world, parent);
}

void ecs_delete(
    ecs_world_t *world,
    ecs_entity_t entity)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(entity != 0, ECS_INVALID_PARAMETER, NULL);

    ecs_stage_t *stage = ecs_stage_from_world(&world);
    if (ecs_defer_delete(world, stage, entity)) {
        return;
    }

    ecs_record_t *r = ecs_sparse_get_sparse(
        world->store.entity_index, ecs_record_t, entity);
    if (r) {
        ecs_entity_info_t info = {0};
        set_info_from_record(entity, &info, r);

        ecs_table_t *table = info.table;
        uint64_t table_id = 0;
        if (table) {
            table_id = table->id;
        }

        if (info.is_watched) {
            /* Make row positive which prevents infinite recursion in case
             * of cyclic delete actions */
            r->row = (-r->row) - 1;

            /* Ensure that the store contains no dangling references to the
             * deleted entity (as a component, or as part of a relation) */
            on_delete_action(world, entity);

            if (r->table) {
                ecs_entities_t to_remove = ecs_type_to_entities(r->table->type);
                update_component_monitors(world, entity, NULL, &to_remove);
            }
        }

        /* If entity has components, remove them. Check if table is still alive,
         * as delete actions could have deleted the table already. */
        if (table_id && ecs_sparse_is_alive(world->store.tables, table_id)) {
            ecs_type_t type = table->type;
            ecs_entities_t to_remove = ecs_type_to_entities(type);
            delete_entity(world, table, info.data, info.row, &to_remove);
            r->table = NULL;
        }

        r->row = 0;

        /* Remove (and invalidate) entity after executing handlers */
        ecs_sparse_remove(world->store.entity_index, entity);
    }

    ecs_defer_flush(world, stage);
}

void ecs_add_type(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_type_t type)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);

    ecs_entities_t components = ecs_type_to_entities(type);
    add_entities(world, entity, &components);
}

void ecs_add_id(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, id), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);

    ecs_entities_t components = { .array = &id, .count = 1 };
    add_entities(world, entity, &components);
}

void ecs_remove_type(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_type_t type)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);

    ecs_entities_t components = ecs_type_to_entities(type);
    remove_entities(world, entity, &components);
}

void ecs_remove_id(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, id), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);

    ecs_entities_t components = { .array = &id, .count = 1 };
    remove_entities(world, entity, &components);
}

// DEPRECATED
void ecs_add_remove_entity(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id_add,
    ecs_id_t id_remove)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, id_add), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, id_remove), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);

    ecs_entities_t components_add = { .array = &id_add, .count = 1 };      
    ecs_entities_t components_remove = { .array = &id_remove, .count = 1 };      
    add_remove(world, entity, &components_add, &components_remove);
}

void ecs_add_remove_type(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_type_t to_add,
    ecs_type_t to_remove)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);

    ecs_entities_t components_add = ecs_type_to_entities(to_add);
    ecs_entities_t components_remove = ecs_type_to_entities(to_remove);
    add_remove(world, entity, &components_add, &components_remove);
}

ecs_entity_t ecs_clone(
    ecs_world_t *world,
    ecs_entity_t dst,
    ecs_entity_t src,
    bool copy_value)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(src != 0, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, src), ECS_INVALID_PARAMETER, NULL);

    ecs_stage_t *stage = ecs_stage_from_world(&world);
    
    if (!dst) {
        dst = ecs_new_id(world);
    }

    if (ecs_defer_clone(world, stage, dst, src, copy_value)) {
        return dst;
    }

    ecs_entity_info_t src_info;
    bool found = ecs_get_info(world, src, &src_info);
    ecs_table_t *src_table = src_info.table;

    if (!found || !src_table) {
        return dst;
    }

    ecs_type_t src_type = src_table->type;
    ecs_entities_t to_add = ecs_type_to_entities(src_type);

    ecs_entity_info_t dst_info = {0};
    dst_info.row = new_entity(world, dst, &dst_info, src_table, &to_add);

    if (copy_value) {
        ecs_table_move(world, dst, src, src_table, dst_info.data, 
            dst_info.row, src_table, src_info.data, src_info.row);

        int i;
        for (i = 0; i < to_add.count; i ++) {
            ecs_run_set_systems(world, &to_add, 
                src_table, src_info.data, dst_info.row, 1, true);
        }
    }

    ecs_defer_flush(world, stage);

    return dst;
}

const void* ecs_get_w_id(
    const ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, id), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_stage_from_readonly_world(world)->asynchronous == false, 
        ECS_INVALID_PARAMETER, NULL);

    /* Make sure we're not working with a stage */
    world = ecs_get_world(world);

    ecs_entity_info_t info;
    void *ptr = NULL;

    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);

    bool found = ecs_get_info(world, entity, &info);
    if (found) {
        if (!info.table) {
            return NULL;
        }

        ptr = get_component(&info, id);
        if (!ptr) {
            if (id != ecs_id(EcsName) && id != EcsPrefab) {
                ptr = get_base_component(
                    world, &info, id);
            }
        }        
    }

    return ptr;
}

const void* ecs_get_ref_w_id(
    const ecs_world_t * world,
    ecs_ref_t * ref,
    ecs_entity_t entity,
    ecs_id_t id)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ref != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!entity || !ref->entity || entity == ref->entity, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!id || !ref->component || id == ref->component, ECS_INVALID_PARAMETER, NULL);
    ecs_record_t *record = ref->record;

    entity |= ref->entity;

    if (!record) {
        /* Make sure we're not working with a stage */
        world = ecs_get_world(world);
        record = ecs_eis_get(world, entity);
    }

    if (!record || !record->table) {
        return NULL;
    }

    ecs_table_t *table = record->table;

    if (ref->record == record &&
        ref->table == table &&
        ref->row == record->row &&
        ref->alloc_count == table->alloc_count)
    {
        return ref->ptr;
    }

    id |= ref->component;

    ref->entity = entity;
    ref->component = id;
    ref->table = table;
    ref->row = record->row;
    ref->alloc_count = table->alloc_count;

    ecs_entity_info_t info = {0};
    set_info_from_record(entity, &info, record);
    ref->ptr = get_component(&info, id);
    ref->record = record;

    return ref->ptr;
}

void* ecs_get_mut_w_id(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id,
    bool * is_added)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, id), ECS_INVALID_PARAMETER, NULL);
    
    ecs_stage_t *stage = ecs_stage_from_world(&world);
    void *result;

    if (ecs_defer_set(
        world, stage, EcsOpMut, entity, id, 0, NULL, &result, is_added))
    {
        return result;
    }

    ecs_entity_info_t info;
    result = get_mutable(world, entity, id, &info, is_added);
    
    /* Store table so we can quickly check if returned pointer is still valid */
    ecs_table_t *table = info.record->table;
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);

    /* Keep track of alloc count of table, since even if the entity has not
     * moved, other entities could have been added to the table which could
     * reallocate arrays. Also store the row, as the entity could have 
     * reallocated. */
    int32_t alloc_count = table->alloc_count;
    int32_t row = info.record->row;
    
    ecs_defer_flush(world, stage);

    /* Ensure that after flushing, the pointer is still valid. Flushing may
     * trigger callbacks, which could do anything with the entity */
    if (table != info.record->table || 
        alloc_count != info.record->table->alloc_count ||
        row != info.record->row) 
    {
        if (ecs_get_info(world, entity, &info) && info.table) {
            result =  get_component(&info, id);
        } else {
            /* A trigger has removed the component we just added. This is not
             * allowed, an application should always be able to assume that
             * get_mut returns a valid pointer. */
            ecs_assert(false, ECS_INVALID_OPERATION, NULL);
        }
    }

    return result;
}

void ecs_modified_w_id(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, id), ECS_INVALID_PARAMETER, NULL);

    ecs_stage_t *stage = ecs_stage_from_world(&world);

    if (ecs_defer_modified(world, stage, entity, id)) {
        return;
    }

    /* If the entity does not have the component, calling ecs_modified is 
     * invalid. The assert needs to happen after the defer statement, as the
     * entity may not have the component when this function is called while
     * operations are being deferred. */
    ecs_assert(ecs_has_id(world, entity, id), 
        ECS_INVALID_PARAMETER, NULL);

    ecs_entity_info_t info = {0};
    if (ecs_get_info(world, entity, &info)) {
        ecs_entities_t added = {
            .array = &id,
            .count = 1
        };
        ecs_run_set_systems(world, &added, 
            info.table, info.data, info.row, 1, false);
    }

    ecs_table_mark_dirty(info.table, id);
    
    ecs_defer_flush(world, stage);
}

static
ecs_entity_t assign_ptr_w_id(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id,
    size_t size,
    void * ptr,
    bool is_move,
    bool notify)
{
    ecs_stage_t *stage = ecs_stage_from_world(&world);

    ecs_entities_t added = {
        .array = &id,
        .count = 1
    };

    if (!entity) {
        entity = ecs_new_id(world);
        ecs_entity_t scope = stage->scope;
        if (scope) {
            ecs_add_pair(world, entity, EcsChildOf, scope);
        }
    }

    if (ecs_defer_set(world, stage, EcsOpSet, entity, id, 
        ecs_from_size_t(size), ptr, NULL, NULL))
    {
        return entity;
    }

    ecs_entity_info_t info;

    void *dst = get_mutable(world, entity, id, &info, NULL);

    /* This can no longer happen since we defer operations */
    ecs_assert(dst != NULL, ECS_INTERNAL_ERROR, NULL);

    if (ptr) {
        ecs_entity_t real_id = ecs_get_typeid(world, id);
        const ecs_type_info_t *cdata = get_c_info(world, real_id);
        if (cdata) {
            if (is_move) {
                ecs_move_t move = cdata->lifecycle.move;
                if (move) {
                    move(world, real_id, &entity, &entity, dst, ptr, size, 1, 
                        cdata->lifecycle.ctx);
                } else {
                    ecs_os_memcpy(dst, ptr, ecs_from_size_t(size));
                }
            } else {
                ecs_copy_t copy = cdata->lifecycle.copy;
                if (copy) {
                    copy(world, real_id, &entity, &entity, dst, ptr, size, 1, 
                        cdata->lifecycle.ctx);
                } else {
                    ecs_os_memcpy(dst, ptr, ecs_from_size_t(size));
                }
            }
        } else {
            ecs_os_memcpy(dst, ptr, ecs_from_size_t(size));
        }
    } else {
        memset(dst, 0, size);
    }

    ecs_table_mark_dirty(info.table, id);

    if (notify) {
        ecs_run_set_systems(world, &added, 
            info.table, info.data, info.row, 1, false);
    }

    ecs_defer_flush(world, stage);

    return entity;
}

ecs_entity_t ecs_set_ptr_w_id(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id,
    size_t size,
    const void *ptr)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!entity || ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, id), ECS_INVALID_PARAMETER, NULL);

    /* Safe to cast away const: function won't modify if move arg is false */
    return assign_ptr_w_id(
        world, entity, id, size, (void*)ptr, false, true);
}

ecs_entity_t ecs_get_case(
    const ecs_world_t *world,
    ecs_entity_t entity,
    ecs_entity_t sw_id)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, sw_id), ECS_INVALID_PARAMETER, NULL);

    ecs_entity_info_t info;
    ecs_table_t *table;
    if (!ecs_get_info(world, entity, &info) || !(table = info.table)) {
        return 0;
    }

    sw_id = sw_id | ECS_SWITCH;

    ecs_type_t type = table->type;
    int32_t index = ecs_type_index_of(type, sw_id);
    if (index == -1) {
        return 0;
    }

    index -= table->sw_column_offset;
    ecs_assert(index >= 0, ECS_INTERNAL_ERROR, NULL);

    /* Data cannot be NULl, since entity is stored in the table */
    ecs_assert(info.data != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_switch_t *sw = info.data->sw_columns[index].data;  
    return ecs_switch_get(sw, info.row);  
}

void ecs_enable_component_w_id(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id,
    bool enable)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, id), ECS_INVALID_PARAMETER, NULL);

    ecs_stage_t *stage = ecs_stage_from_world(&world);

    if (ecs_defer_enable(
        world, stage, entity, id, enable))
    {
        return;
    } else {
        /* Operations invoked by enable/disable should not be deferred */
        stage->defer --;
    }

    ecs_entity_info_t info;
    ecs_get_info(world, entity, &info);

    ecs_entity_t bs_id = (id & ECS_COMPONENT_MASK) | ECS_DISABLED;
    
    ecs_table_t *table = info.table;
    int32_t index = -1;
    if (table) {
        index = ecs_type_index_of(table->type, bs_id);
    }

    if (index == -1) {
        ecs_add_id(world, entity, bs_id);
        ecs_enable_component_w_id(world, entity, id, enable);
        return;
    }

    index -= table->bs_column_offset;
    ecs_assert(index >= 0, ECS_INTERNAL_ERROR, NULL);

    /* Data cannot be NULl, since entity is stored in the table */
    ecs_assert(info.data != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_bitset_t *bs = &info.data->bs_columns[index].data;
    ecs_assert(bs != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_bitset_set(bs, info.row, enable);
}

bool ecs_is_component_enabled_w_id(
    const ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, id), ECS_INVALID_PARAMETER, NULL);

    /* Make sure we're not working with a stage */
    world = ecs_get_world(world);

    ecs_entity_info_t info;
    ecs_table_t *table;
    if (!ecs_get_info(world, entity, &info) || !(table = info.table)) {
        return false;
    }

    ecs_entity_t bs_id = (id & ECS_COMPONENT_MASK) | ECS_DISABLED;

    ecs_type_t type = table->type;
    int32_t index = ecs_type_index_of(type, bs_id);
    if (index == -1) {
        /* If table does not have DISABLED column for component, component is
         * always enabled, if the entity has it */
        return ecs_has_id(world, entity, id);
    }

    index -= table->bs_column_offset;
    ecs_assert(index >= 0, ECS_INTERNAL_ERROR, NULL);

    /* Data cannot be NULl, since entity is stored in the table */
    ecs_assert(info.data != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_bitset_t *bs = &info.data->bs_columns[index].data;  

    return ecs_bitset_get(bs, info.row);
}

bool ecs_has_id(
    const ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!id || ecs_is_valid(world, id), ECS_INVALID_PARAMETER, NULL);

    /* Make sure we're not working with a stage */
    world = ecs_get_world(world);

    if (ECS_HAS_ROLE(id, CASE)) {
        ecs_entity_info_t info;
        ecs_table_t *table;
        if (!ecs_get_info(world, entity, &info) || !(table = info.table)) {
            return false;
        }

        int32_t index = ecs_table_switch_from_case(world, table, id);
        ecs_assert(index < table->sw_column_count, ECS_INTERNAL_ERROR, NULL);
        
        ecs_data_t *data = info.data;
        ecs_switch_t *sw = data->sw_columns[index].data;
        ecs_entity_t value = ecs_switch_get(sw, info.row);

        return value == (id & ECS_COMPONENT_MASK);
    } else {
        ecs_type_t type = ecs_get_type(world, entity);
        return ecs_type_has_id(world, type, id);
    }
}

bool ecs_has_type(
    const ecs_world_t *world,
    ecs_entity_t entity,
    ecs_type_t type)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);
    return has_type(world, entity, type, true, true);
}

ecs_entity_t ecs_get_object_w_id(
    const ecs_world_t *world,
    ecs_entity_t entity,
    ecs_entity_t rel,
    ecs_id_t id)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!entity || ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!id || ecs_is_valid(world, id), ECS_INVALID_PARAMETER, NULL);

    if (!entity) {
        return 0;
    }

    ecs_type_t type = ecs_get_type(world, entity);    
    ecs_entity_t object = ecs_find_in_type(world, type, id, rel);
    return object;
}

const char* ecs_get_name(
    const ecs_world_t *world,
    ecs_entity_t entity)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);

    const EcsName *id = ecs_get(world, entity, EcsName);

    if (id) {
        return id->value;
    } else {
        return NULL;
    }
}

ecs_type_t ecs_type_from_id(
    ecs_world_t *world,
    ecs_id_t id)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, id), ECS_INVALID_PARAMETER, NULL);

    if (!id) {
        return NULL;
    }

    const EcsType *type = ecs_get(world, id, EcsType);
    if (type) {
        return type->normalized;
    }

    return ecs_type_find(world, &id, 1);
}

ecs_id_t ecs_type_to_id(
    const ecs_world_t *world, 
    ecs_type_t type)
{
    (void)world;

    if (!type) {
        return 0;
    }
    
    /* If array contains n entities, it cannot be reduced to a single entity */
    if (ecs_vector_count(type) != 1) {
        ecs_abort(ECS_TYPE_NOT_AN_ENTITY, NULL);
    }

    return *(ecs_vector_first(type, ecs_id_t));
}

ecs_id_t ecs_make_pair(
    ecs_entity_t relation,
    ecs_entity_t object)
{
    return ecs_pair(relation, object);
}

bool ecs_is_valid(
    const ecs_world_t *world,
    ecs_entity_t entity)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);

    /* 0 is not a valid entity id */
    if (!entity) {
        return false;
    }
    
    /* Make sure we're not working with a stage */
    world = ecs_get_world(world);

    /* When checking roles and/or pairs, the generation count may have been
     * stripped away. Just test if the entity is 0 or not. */
    if (ECS_HAS_ROLE(entity, PAIR)) {
        ecs_entity_t lo = ECS_PAIR_OBJECT(entity);
        ecs_entity_t hi = ECS_PAIR_RELATION(entity);
        return lo != 0 && hi != 0;
    } else
    if (entity & ECS_ROLE) {
        return ecs_entity_t_lo(entity) != 0;
    }

    /* An id may not yet exist in the world which does not mean it cannot be
     * used as an entity identifier. An example is when a hard-coded entity id
     * is used. However, if the entity id does exist in the world, it must be
     * alive. */
    return !ecs_exists(world, entity) || ecs_is_alive(world, entity);
}

bool ecs_is_alive(
    const ecs_world_t *world,
    ecs_entity_t entity)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(entity != 0, ECS_INVALID_PARAMETER, NULL);

    /* Make sure we're not working with a stage */
    world = ecs_get_world(world);

    return ecs_eis_is_alive(world, entity);
}

ecs_entity_t ecs_get_alive(
    const ecs_world_t *world,
    ecs_entity_t entity)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(entity != 0, ECS_INVALID_PARAMETER, NULL);

    if (ecs_is_alive(world, entity)) {
        return entity;
    }

    /* Make sure id does not have generation. This guards against accidentally
     * "upcasting" a not alive identifier to a alive one. */
    ecs_assert((uint32_t)entity == entity, ECS_INVALID_PARAMETER, NULL);

    /* Make sure we're not working with a stage */
    world = ecs_get_world(world);

    ecs_entity_t current = ecs_eis_get_current(world, entity);
    if (!current || !ecs_is_alive(world, current)) {
        return 0;
    }

    return current;
}

void ecs_ensure(
    ecs_world_t *world,
    ecs_entity_t entity)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(entity != 0, ECS_INVALID_PARAMETER, NULL);

    if (ecs_eis_is_alive(world, entity)) {
        /* Nothing to be done, already alive */
        return;
    }

    /* Ensure id exists. The underlying datastructure will verify that the
     * generation count matches the provided one. */
    ecs_eis_ensure(world, entity);
}

bool ecs_exists(
    const ecs_world_t *world,
    ecs_entity_t entity)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(entity != 0, ECS_INVALID_PARAMETER, NULL);

    /* Make sure we're not working with a stage */
    world = ecs_get_world(world);

    return ecs_eis_exists(world, entity);
}

ecs_type_t ecs_get_type(
    const ecs_world_t *world,
    ecs_entity_t entity)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, entity), ECS_INVALID_PARAMETER, NULL);
    
    /* Make sure we're not working with a stage */
    world = ecs_get_world(world);

    ecs_record_t *record = ecs_eis_get(world, entity);
    ecs_table_t *table;
    if (record && (table = record->table)) {
        return table->type;
    }
    
    return NULL;
}

ecs_id_t ecs_get_typeid(
    const ecs_world_t *world,
    ecs_id_t id)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, id), ECS_INVALID_PARAMETER, NULL);

    if (ECS_HAS_ROLE(id, PAIR)) {
        /* Make sure we're not working with a stage */
        world = ecs_get_world(world);

        ecs_entity_t rel = ecs_get_alive(world, ECS_PAIR_RELATION(id));
        if (ecs_has(world, rel, EcsComponent)) {
            /* This is not a pair object, relation is the value */
            return rel;
        } else {
            /* This is a pair object, object is the value */
            return ecs_get_alive(world, ECS_PAIR_OBJECT(id));
        }
    } else if (id & ECS_ROLE_MASK) {
        return 0;
    }

    return id;
}

int32_t ecs_count_type(
    const ecs_world_t *world,
    ecs_type_t type)
{    
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);

    if (!type) {
        return 0;
    }

    /* Make sure we're not working with a stage */
    world = ecs_get_world(world);

    return ecs_count_filter(world, &(ecs_filter_t){
        .include = type
    });
}

int32_t ecs_count_id(
    const ecs_world_t *world,
    ecs_entity_t entity)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);

    if (!entity) {
        return 0;
    }

    /* Make sure we're not working with a stage */
    world = ecs_get_world(world);

    /* Get temporary type that just contains entity */
    ECS_VECTOR_STACK(type, ecs_entity_t, &entity, 1);

    return ecs_count_filter(world, &(ecs_filter_t){
        .include = type
    });
}

int32_t ecs_count_filter(
    const ecs_world_t *world,
    const ecs_filter_t *filter)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);

    /* Make sure we're not working with a stage */
    world = ecs_get_world(world);

    ecs_sparse_t *tables = world->store.tables;
    int32_t i, count = ecs_sparse_count(tables);
    int32_t result = 0;

    for (i = 0; i < count; i ++) {
        ecs_table_t *table = ecs_sparse_get(tables, ecs_table_t, i);
        if (!filter || ecs_table_match_filter(world, table, filter)) {
            result += ecs_table_count(table);
        }
    }
    
    return result;
}

bool ecs_defer_begin(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_stage_t *stage = ecs_stage_from_world(&world);
    return ecs_defer_none(world, stage);
}

bool ecs_defer_end(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_stage_t *stage = ecs_stage_from_world(&world);
    return ecs_defer_flush(world, stage);
}

static
size_t append_to_str(
    char **buffer,
    const char *str,
    size_t bytes_left,
    size_t *required)
{
    char *ptr = *buffer;

    size_t len = strlen(str);
    size_t to_write;
    if (bytes_left < len) {
        to_write = bytes_left;
        bytes_left = 0;
    } else {
        to_write = len;
        bytes_left -= len;
    }
    
    if (to_write) {
        ecs_os_memcpy(ptr, str, to_write);
    }

    (*required) += len;
    (*buffer) += to_write;

    return bytes_left;
}

const char* ecs_role_str(
    ecs_entity_t entity)
{
    if (ECS_HAS_ROLE(entity, CHILDOF)) {
        return "CHILDOF";
    } else
    if (ECS_HAS_ROLE(entity, INSTANCEOF)) {
        return "INSTANCEOF";
    } else
    if (ECS_HAS_ROLE(entity, PAIR)) {
        return "PAIR";
    } else
    if (ECS_HAS_ROLE(entity, DISABLED)) {
        return "DISABLED";
    } else    
    if (ECS_HAS_ROLE(entity, XOR)) {
        return "XOR";
    } else
    if (ECS_HAS_ROLE(entity, OR)) {
        return "OR";
    } else
    if (ECS_HAS_ROLE(entity, AND)) {
        return "AND";
    } else
    if (ECS_HAS_ROLE(entity, NOT)) {
        return "NOT";
    } else
    if (ECS_HAS_ROLE(entity, SWITCH)) {
        return "SWITCH";
    } else
    if (ECS_HAS_ROLE(entity, CASE)) {
        return "CASE";
    } else
    if (ECS_HAS_ROLE(entity, OWNED)) {
        return "OWNED";
    } else {
        return "UNKNOWN";
    }
}

size_t ecs_id_str(
    const ecs_world_t *world,
    ecs_id_t id,
    char *buffer,
    size_t buffer_len)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_is_valid(world, id), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(buffer != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(buffer_len > 0, ECS_INVALID_PARAMETER, NULL);

    world = ecs_get_world(world);

    char *ptr = buffer;
    size_t bytes_left = buffer_len - 1, required = 0;
    if (id & ECS_ROLE_MASK && !ECS_HAS_ROLE(id, PAIR)) {
        const char *role = ecs_role_str(id);
        bytes_left = append_to_str(&ptr, role, bytes_left, &required);
        bytes_left = append_to_str(&ptr, "|", bytes_left, &required);
    }

    ecs_entity_t e = id & ECS_COMPONENT_MASK;

    if (ECS_HAS_ROLE(id, PAIR)) {
        ecs_entity_t lo = ECS_PAIR_OBJECT(id);
        ecs_entity_t hi = ECS_PAIR_RELATION(id);

        lo = ecs_get_alive(world, lo);
        hi = ecs_get_alive(world, hi);

        if (hi) {
            char *hi_path = ecs_get_fullpath(world, hi);
            bytes_left = append_to_str(&ptr, "(", bytes_left, &required);
            bytes_left = append_to_str(&ptr, hi_path, bytes_left, &required);
            ecs_os_free(hi_path);
            bytes_left = append_to_str(&ptr, ",", bytes_left, &required);
        }            
        char *lo_path = ecs_get_fullpath(world, lo);
        bytes_left = append_to_str(&ptr, lo_path, bytes_left, &required);
        ecs_os_free(lo_path);

        if (hi) {
            bytes_left = append_to_str(&ptr, ")", bytes_left, &required);
        }
    } else {
        char *path = ecs_get_fullpath(world, e);
        bytes_left = append_to_str(&ptr, path, bytes_left, &required);
        ecs_os_free(path);
    }

    ptr[0] = '\0';
    return required;
}

static
void flush_bulk_new(
    ecs_world_t * world,
    ecs_op_t * op)
{
    ecs_entity_t *ids = op->is._n.entities;
    void **bulk_data = op->is._n.bulk_data;
    if (bulk_data) {
        ecs_entity_t *components = op->components.array;
        int c, c_count = op->components.count;
        for (c = 0; c < c_count; c ++) {
            ecs_entity_t component = components[c];
            const EcsComponent *cptr = ecs_component_from_id(world, component);
            ecs_assert(cptr != NULL, ECS_INTERNAL_ERROR, NULL);
            size_t size = ecs_to_size_t(cptr->size);
            void *ptr, *data = bulk_data[c];
            int i, count = op->is._n.count;
            for (i = 0, ptr = data; i < count; i ++, ptr = ECS_OFFSET(ptr, size)) {
                assign_ptr_w_id(world, ids[i], component, size, ptr, 
                    true, true);
            }
            ecs_os_free(data);
        }
        ecs_os_free(bulk_data);
    } else {
        int i, count = op->is._n.count;
        for (i = 0; i < count; i ++) {
            add_entities(world, ids[i], &op->components);
        }
    }

    if (op->components.count > 1) {
        ecs_os_free(op->components.array);
    }

    ecs_os_free(ids);
}

static
void discard_op(
    ecs_op_t * op)
{
    ecs_assert(op->kind != EcsOpBulkNew, ECS_INTERNAL_ERROR, NULL);

    void *value = op->is._1.value;
    if (value) {
        ecs_os_free(value);
    }

    ecs_entity_t *components = op->components.array;
    if (components) {
        ecs_os_free(components);
    }
}

static
bool valid_components(
    ecs_world_t * world,
    ecs_entities_t * entities)
{
    ecs_entity_t *array = entities->array;
    int32_t i, count = entities->count;
    for (i = 0; i < count; i ++) {
        ecs_entity_t e = array[i];
        if (ECS_HAS_RELATION(e, EcsChildOf)) {
            e = ecs_entity_t_lo(e);
            if (ecs_exists(world, e) && !ecs_is_alive(world, e)) {
                return false;
            }
        }
    }
    return true;
}

/* Leave safe section. Run all deferred commands. */
bool ecs_defer_flush(
    ecs_world_t *world,
    ecs_stage_t *stage)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(stage != NULL, ECS_INVALID_PARAMETER, NULL);

    if (!--stage->defer) {
        /* Set to NULL. Processing deferred commands can cause additional
         * commands to get enqueued (as result of reactive systems). Make sure
         * that the original array is not reallocated, as this would complicate
         * processing the queue. */
        ecs_vector_t *defer_queue = stage->defer_queue;
        stage->defer_queue = NULL;

        if (defer_queue) {
            ecs_op_t *ops = ecs_vector_first(defer_queue, ecs_op_t);
            int32_t i, count = ecs_vector_count(defer_queue);
            
            for (i = 0; i < count; i ++) {
                ecs_op_t *op = &ops[i];
                ecs_entity_t e = op->is._1.entity;
                if (op->kind == EcsOpBulkNew) {
                    e = 0;
                }

                /* If entity is no longer alive, this could be because the queue
                * contained both a delete and a subsequent add/remove/set which
                * should be ignored. */
                if (e && !ecs_is_alive(world, e) && ecs_eis_exists(world, e)) {
                    ecs_assert(op->kind != EcsOpNew && op->kind != EcsOpClone, 
                        ECS_INTERNAL_ERROR, NULL);
                    world->discard_count ++;
                    discard_op(op);
                    continue;
                }

                if (op->components.count == 1) {
                    op->components.array = &op->component;
                }

                switch(op->kind) {
                case EcsOpNew:
                    if (op->scope) {
                        ecs_add_pair(world, e, EcsChildOf, op->scope);
                    }
                    /* Fallthrough */
                case EcsOpAdd:
                    if (valid_components(world, &op->components)) {
                        world->add_count ++;
                        add_entities(world, e, &op->components);
                    } else {
                        ecs_delete(world, e);
                    }
                    break;
                case EcsOpRemove:
                    remove_entities(world, e, &op->components);
                    break;
                case EcsOpClone:
                    ecs_clone(world, e, op->component, op->is._1.clone_value);
                    break;
                case EcsOpSet:
                    assign_ptr_w_id(world, e, 
                        op->component, ecs_to_size_t(op->is._1.size), 
                        op->is._1.value, true, true);
                    break;
                case EcsOpMut:
                    assign_ptr_w_id(world, e, 
                        op->component, ecs_to_size_t(op->is._1.size), 
                        op->is._1.value, true, false);
                    break;
                case EcsOpModified:
                    ecs_modified_w_id(world, e, op->component);
                    break;
                case EcsOpDelete: {
                    ecs_delete(world, e);
                    break;
                }
                case EcsOpEnable:
                    ecs_enable_component_w_id(
                        world, e, op->component, true);
                    break;
                case EcsOpDisable:
                    ecs_enable_component_w_id(
                        world, e, op->component, false);
                    break;
                case EcsOpClear:
                    ecs_clear(world, e);
                    break;
                case EcsOpBulkNew:
                    flush_bulk_new(world, op);

                    /* Continue since flush_bulk_new is repsonsible for cleaning
                    * up resources. */
                    continue;
                }

                if (op->components.count > 1) {
                    ecs_os_free(op->components.array);
                }

                if (op->is._1.value) {
                    ecs_os_free(op->is._1.value);
                }                  
            }

            if (stage->defer_queue) {
                ecs_vector_free(stage->defer_queue);
            }

            /* Restore defer queue */
            ecs_vector_clear(defer_queue);
            stage->defer_queue = defer_queue;
        }

        return true;
    }

    return false;
}

static
ecs_op_t* new_defer_op(ecs_stage_t *stage) {
    ecs_op_t *result = ecs_vector_add(&stage->defer_queue, ecs_op_t);
    ecs_os_memset(result, 0, ECS_SIZEOF(ecs_op_t));
    return result;
}

static 
void new_defer_component_ids(
    ecs_op_t *op, 
    const ecs_entities_t *components)
{
    int32_t components_count = components->count;
    if (components_count == 1) {
        ecs_entity_t component = components->array[0];
        op->component = component;
        op->components = (ecs_entities_t) {
            .array = NULL,
            .count = 1
        };
    } else if (components_count) {
        ecs_size_t array_size = components_count * ECS_SIZEOF(ecs_entity_t);
        op->components.array = ecs_os_malloc(array_size);
        ecs_os_memcpy(op->components.array, components->array, array_size);
        op->components.count = components_count;
    } else {
        op->component = 0;
        op->components = (ecs_entities_t){ 0 };
    }
}

static
bool defer_add_remove(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_op_kind_t op_kind,
    ecs_entity_t entity,
    ecs_entities_t *components)
{
    if (stage->defer) {
        ecs_entity_t scope = stage->scope;
        if (components) {
            if (!components->count && !scope) {
                return true;
            }
        }

        ecs_op_t *op = new_defer_op(stage);
        op->kind = op_kind;
        op->scope = scope;
        op->is._1.entity = entity;

        new_defer_component_ids(op, components);

        if (op_kind == EcsOpNew) {
            world->new_count ++;
        } else if (op_kind == EcsOpAdd) {
            world->add_count ++;
        } else if (op_kind == EcsOpRemove) {
            world->remove_count ++;
        }

        return true;
    } else {
        stage->defer ++;
    }
    
    return false;
}

static
void merge_stages(
    ecs_world_t *world,
    bool force_merge)
{
    bool is_stage = world->magic == ECS_STAGE_MAGIC;
    ecs_stage_t *stage = ecs_stage_from_world(&world);

    bool measure_frame_time = world->measure_frame_time;

    ecs_time_t t_start;
    if (measure_frame_time) {
        ecs_os_get_time(&t_start);
    }

    if (is_stage) {
        /* Check for consistency if force_merge is enabled. In practice this
         * function will never get called with force_merge disabled for just
         * a single stage. */
        if (force_merge || stage->auto_merge) {
            ecs_defer_end((ecs_world_t*)stage);
        }
    } else {
        /* Merge stages. Only merge if the stage has auto_merging turned on, or 
         * if this is a forced merge (like when ecs_merge is called) */
        int32_t i, count = ecs_get_stage_count(world);
        for (i = 0; i < count; i ++) {
            ecs_stage_t *s = (ecs_stage_t*)ecs_get_stage(world, i);
            ecs_assert(s->magic == ECS_STAGE_MAGIC, ECS_INTERNAL_ERROR, NULL);
            if (force_merge || s->auto_merge) {
                ecs_defer_end((ecs_world_t*)s);
            }
        }
    }

    ecs_eval_component_monitors(world);

    if (measure_frame_time) {
        world->stats.merge_time_total += 
            (FLECS_FLOAT)ecs_time_measure(&t_start);
    }

    world->stats.merge_count_total ++; 

    /* If stage is asynchronous, deferring is always enabled */
    if (stage->asynchronous) {
        ecs_defer_begin((ecs_world_t*)stage);
    }
}

static
void do_auto_merge(
    ecs_world_t *world)
{
    merge_stages(world, false);
}

static
void do_manual_merge(
    ecs_world_t *world)
{
    merge_stages(world, true);
}

bool ecs_defer_none(
    ecs_world_t *world,
    ecs_stage_t *stage)
{
    (void)world;
    return (++ stage->defer) == 1;
}

bool ecs_defer_modified(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity,
    ecs_entity_t component)
{
    (void)world;
    if (stage->defer) {
        ecs_op_t *op = new_defer_op(stage);
        op->kind = EcsOpModified;
        op->component = component;
        op->is._1.entity = entity;
        return true;
    } else {
        stage->defer ++;
    }
    
    return false;
}

bool ecs_defer_clone(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity,
    ecs_entity_t src,
    bool clone_value)
{   
    (void)world;
    if (stage->defer) {
        ecs_op_t *op = new_defer_op(stage);
        op->kind = EcsOpClone;
        op->component = src;
        op->is._1.entity = entity;
        op->is._1.clone_value = clone_value;
        return true;
    } else {
        stage->defer ++;
    }
    
    return false;   
}

bool ecs_defer_delete(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity)
{
    (void)world;
    if (stage->defer) {
        ecs_op_t *op = new_defer_op(stage);
        op->kind = EcsOpDelete;
        op->is._1.entity = entity;
        world->delete_count ++;
        return true;
    } else {
        stage->defer ++;
    }
    return false;
}

bool ecs_defer_clear(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity)
{
    (void)world;
    if (stage->defer) {
        ecs_op_t *op = new_defer_op(stage);
        op->kind = EcsOpClear;
        op->is._1.entity = entity;
        world->clear_count ++;
        return true;
    } else {
        stage->defer ++;
    }
    return false;
}

bool ecs_defer_enable(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity,
    ecs_entity_t component,
    bool enable)
{
    (void)world;
    if (stage->defer) {
        ecs_op_t *op = new_defer_op(stage);
        op->kind = enable ? EcsOpEnable : EcsOpDisable;
        op->is._1.entity = entity;
        op->component = component;
        return true;
    } else {
        stage->defer ++;
    }
    return false;
}

bool ecs_defer_bulk_new(
    ecs_world_t *world,
    ecs_stage_t *stage,
    int32_t count,
    const ecs_entities_t *components_ids,
    void **component_data,
    const ecs_entity_t **ids_out)
{
    if (stage->defer) {
        ecs_entity_t *ids = ecs_os_malloc(count * ECS_SIZEOF(ecs_entity_t));
        void **defer_data = NULL;

        world->bulk_new_count ++;

        /* Use ecs_new_id as this is thread safe */
        int i;
        for (i = 0; i < count; i ++) {
            ids[i] = ecs_new_id(world);
        }

        /* Create private copy for component data */
        if (component_data) {
            int c, c_count = components_ids->count;
            ecs_entity_t *components = components_ids->array;
            defer_data = ecs_os_malloc(ECS_SIZEOF(void*) * c_count);
            for (c = 0; c < c_count; c ++) {
                ecs_entity_t comp = components[c];
                const EcsComponent *cptr = ecs_component_from_id(world, comp);
                ecs_assert(cptr != NULL, ECS_INVALID_PARAMETER, NULL);

                ecs_size_t size = cptr->size;
                void *data = ecs_os_malloc(size * count);
                defer_data[c] = data;

                const ecs_type_info_t *cinfo = NULL;
                ecs_entity_t real_id = ecs_get_typeid(world, comp);
                if (real_id) {
                    cinfo = ecs_get_c_info(world, real_id);
                }
                ecs_xtor_t ctor;
                if (cinfo && (ctor = cinfo->lifecycle.ctor)) {
                    void *ctx = cinfo->lifecycle.ctx;
                    ctor(world, comp, ids, data, ecs_to_size_t(size), count, ctx);
                    ecs_move_t move;
                    if ((move = cinfo->lifecycle.move)) {
                        move(world, comp, ids, ids, data, component_data[c], 
                            ecs_to_size_t(size), count, ctx);
                    } else {
                        ecs_os_memcpy(data, component_data[c], size * count);
                    }
                } else {
                    ecs_os_memcpy(data, component_data[c], size * count);
                }
            }
        }

        /* Store data in op */
        ecs_op_t *op = new_defer_op(stage);
        op->kind = EcsOpBulkNew;
        op->is._n.entities = ids;
        op->is._n.bulk_data = defer_data;
        op->is._n.count = count;
        new_defer_component_ids(op, components_ids);
        *ids_out = ids;

        return true;
    } else {
        stage->defer ++;
    }

    return false;
}

bool ecs_defer_new(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity,
    ecs_entities_t *components)
{   
    return defer_add_remove(world, stage, EcsOpNew, entity, components);
}

bool ecs_defer_add(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity,
    ecs_entities_t *components)
{   
    return defer_add_remove(world, stage, EcsOpAdd, entity, components);
}

bool ecs_defer_remove(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t entity,
    ecs_entities_t *components)
{
    return defer_add_remove(world, stage, EcsOpRemove, entity, components);
}

bool ecs_defer_set(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_op_kind_t op_kind,
    ecs_entity_t entity,
    ecs_entity_t component,
    ecs_size_t size,
    const void *value,
    void **value_out,
    bool *is_added)
{
    if (stage->defer) {
        world->set_count ++;
        if (!size) {
            const EcsComponent *cptr = ecs_component_from_id(world, component);
            ecs_assert(cptr != NULL, ECS_INVALID_PARAMETER, NULL);
            size = cptr->size;
        }

        ecs_op_t *op = new_defer_op(stage);
        op->kind = op_kind;
        op->component = component;
        op->is._1.entity = entity;
        op->is._1.size = size;
        op->is._1.value = ecs_os_malloc(size);

        if (!value) {
            value = ecs_get_w_id(world, entity, component);
            if (is_added) {
                *is_added = value == NULL;
            }
        }

        const ecs_type_info_t *c_info = NULL;
        ecs_entity_t real_id = ecs_get_typeid(world, component);
        if (real_id) {
            c_info = ecs_get_c_info(world, real_id);
        }
        ecs_xtor_t ctor;
        if (c_info && (ctor = c_info->lifecycle.ctor)) {
            ctor(world, component, &entity, op->is._1.value, 
                ecs_to_size_t(size), 1, c_info->lifecycle.ctx);

            ecs_copy_t copy;
            if (value) {
                if ((copy = c_info->lifecycle.copy)) {
                    copy(world, component, &entity, &entity, op->is._1.value, value, 
                        ecs_to_size_t(size), 1, c_info->lifecycle.ctx);
                } else {
                    ecs_os_memcpy(op->is._1.value, value, size);
                }
            }
        } else if (value) {
            ecs_os_memcpy(op->is._1.value, value, size);
        }
        
        if (value_out) {
            *value_out = op->is._1.value;
        }

        return true;
    } else {
        stage->defer ++;
    }
    
    return false;
}

void ecs_stage_merge_post_frame(
    ecs_world_t *world,
    ecs_stage_t *stage)
{
    /* Execute post frame actions */
    ecs_vector_each(stage->post_frame_actions, ecs_action_elem_t, action, {
        action->action(world, action->ctx);
    });

    ecs_vector_free(stage->post_frame_actions);
    stage->post_frame_actions = NULL;
}

void ecs_stage_init(
    ecs_world_t *world,
    ecs_stage_t *stage)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_PARAMETER, NULL);

    memset(stage, 0, sizeof(ecs_stage_t));

    stage->magic = ECS_STAGE_MAGIC;
    stage->world = world;
    stage->thread_ctx = world;
    stage->auto_merge = true;
    stage->asynchronous = false;
}

void ecs_stage_deinit(
    ecs_world_t *world,
    ecs_stage_t *stage)
{
    (void)world;
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(stage->magic == ECS_STAGE_MAGIC, ECS_INVALID_PARAMETER, NULL);

    /* Make sure stage has no unmerged data */
    ecs_assert(ecs_vector_count(stage->defer_queue) == 0, 
        ECS_INVALID_PARAMETER, NULL);

    /* Set magic to 0 so that accessing the stage after deinitializing it will
     * throw an assert. */
    stage->magic = 0;

    ecs_vector_free(stage->defer_queue);
}

void ecs_set_stages(
    ecs_world_t *world,
    int32_t stage_count)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_PARAMETER, NULL);

    ecs_stage_t *stages;
    int32_t i, count = ecs_vector_count(world->worker_stages);

    if (count && count != stage_count) {
        stages = ecs_vector_first(world->worker_stages, ecs_stage_t);

        for (i = 0; i < count; i ++) {
            /* If stage contains a thread handle, ecs_set_threads was used to
             * create the stages. ecs_set_threads and ecs_set_stages should not
             * be mixed. */
            ecs_assert(stages[i].magic == ECS_STAGE_MAGIC, 
                ECS_INTERNAL_ERROR, NULL);
            ecs_assert(stages[i].thread == 0, ECS_INVALID_OPERATION, NULL);
            ecs_stage_deinit(world, &stages[i]);
        }

        ecs_vector_free(world->worker_stages);
    }
    
    if (stage_count) {
        world->worker_stages = ecs_vector_new(ecs_stage_t, stage_count);

        for (i = 0; i < stage_count; i ++) {
            ecs_stage_t *stage = ecs_vector_add(
                &world->worker_stages, ecs_stage_t);
            ecs_stage_init(world, stage);
            stage->id = 1 + i; /* 0 is reserved for main/temp stage */

            /* Set thread_ctx to stage, as this stage might be used in a
             * multithreaded context */
            stage->thread_ctx = (ecs_world_t*)stage;
        }
    } else {
        /* Set to NULL to prevent double frees */
        world->worker_stages = NULL;
    }

    /* Regardless of whether the stage was just initialized or not, when the
     * ecs_set_stages function is called, all stages inherit the auto_merge
     * property from the world */
    for (i = 0; i < stage_count; i ++) {
        ecs_stage_t *stage = (ecs_stage_t*)ecs_get_stage(world, i);
        stage->auto_merge = world->stage.auto_merge;
    }
}

int32_t ecs_get_stage_count(
    const ecs_world_t *world)
{
    world = ecs_get_world(world);
    return ecs_vector_count(world->worker_stages);
}

int32_t ecs_get_stage_id(
    const ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);

    if (world->magic == ECS_STAGE_MAGIC) {
        ecs_stage_t *stage = (ecs_stage_t*)world;

        /* Index 0 is reserved for main stage */
        return stage->id - 1;
    } else if (world->magic == ECS_WORLD_MAGIC) {
        return 0;
    } else {
        ecs_abort(ECS_INTERNAL_ERROR, NULL);
    }
}

ecs_world_t* ecs_get_stage(
    const ecs_world_t *world,
    int32_t stage_id)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_vector_count(world->worker_stages) > stage_id, 
        ECS_INVALID_PARAMETER, NULL);

    return (ecs_world_t*)ecs_vector_get(
        world->worker_stages, ecs_stage_t, stage_id);
}

bool ecs_staging_begin(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_PARAMETER, NULL);

    int32_t i, count = ecs_get_stage_count(world);
    for (i = 0; i < count; i ++) {
        ecs_defer_begin(ecs_get_stage(world, i));
    }

    bool is_readonly = world->is_readonly;

    /* From this point on, the world is "locked" for mutations, and it is only 
     * allowed to enqueue commands from stages */
    world->is_readonly = true;

    return is_readonly;
}

void ecs_staging_end(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->is_readonly == true, ECS_INVALID_OPERATION, NULL);

    /* After this it is safe again to mutate the world directly */
    world->is_readonly = false;

    do_auto_merge(world);
}

void ecs_merge(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC || 
               world->magic == ECS_STAGE_MAGIC, ECS_INVALID_PARAMETER, NULL);
    do_manual_merge(world);
}

void ecs_set_automerge(
    ecs_world_t *world,
    bool auto_merge)
{
    /* If a world is provided, set auto_merge globally for the world. This
     * doesn't actually do anything (the main stage never merges) but it serves
     * as the default for when stages are created. */
    if (world->magic == ECS_WORLD_MAGIC) {
        world->stage.auto_merge = auto_merge;

        /* Propagate change to all stages */
        int i, stage_count = ecs_get_stage_count(world);
        for (i = 0; i < stage_count; i ++) {
            ecs_stage_t *stage = (ecs_stage_t*)ecs_get_stage(world, i);
            stage->auto_merge = auto_merge;
        }

    /* If a stage is provided, override the auto_merge value for the individual
     * stage. This allows an application to control per-stage which stage should
     * be automatically merged and which one shouldn't */
    } else {
        /* Magic needs to be either a world or a stage */
        ecs_assert(world->magic == ECS_STAGE_MAGIC, 
            ECS_INVALID_FROM_WORKER, NULL);

        ecs_stage_t *stage = (ecs_stage_t*)world;
        stage->auto_merge = auto_merge;
    }
}

bool ecs_stage_is_readonly(
    const ecs_world_t *stage)
{
    const ecs_world_t *world = ecs_get_world(stage);

    if (stage->magic == ECS_STAGE_MAGIC) {
        if (((ecs_stage_t*)stage)->asynchronous) {
            return false;
        }
    }

    if (world->is_readonly) {
        if (stage->magic == ECS_WORLD_MAGIC) {
            return true;
        }
    } else {
        if (stage->magic == ECS_STAGE_MAGIC) {
            return true;
        }
    }

    return false;
}

ecs_world_t* ecs_async_stage_new(
    ecs_world_t *world)
{
    ecs_stage_t *stage = ecs_os_calloc(sizeof(ecs_stage_t));
    ecs_stage_init(world, stage);

    stage->id = -1;
    stage->auto_merge = false;
    stage->asynchronous = true;

    ecs_defer_begin((ecs_world_t*)stage);

    return (ecs_world_t*)stage;
}

void ecs_async_stage_free(
    ecs_world_t *world)
{
    ecs_assert(world->magic == ECS_STAGE_MAGIC, ECS_INVALID_PARAMETER, NULL);
    ecs_stage_t *stage = (ecs_stage_t*)world;
    ecs_assert(stage->asynchronous == true, ECS_INVALID_PARAMETER, NULL);
    ecs_stage_deinit(stage->world, stage);
    ecs_os_free(stage);
}

bool ecs_stage_is_async(
    ecs_world_t *stage)
{
    if (!stage) {
        return false;
    }
    
    if (stage->magic != ECS_STAGE_MAGIC) {
        return false;
    }

    return ((ecs_stage_t*)stage)->asynchronous;
}

/** Resize the vector buffer */
static
ecs_vector_t* resize(
    ecs_vector_t *vector,
    int16_t offset,
    int32_t size)
{
    ecs_vector_t *result = ecs_os_realloc(vector, offset + size);
    ecs_assert(result != NULL, ECS_OUT_OF_MEMORY, 0);
    return result;
}

/* -- Public functions -- */

ecs_vector_t* _ecs_vector_new(
    ecs_size_t elem_size,
    int16_t offset,
    int32_t elem_count)
{
    ecs_assert(elem_size != 0, ECS_INTERNAL_ERROR, NULL);
    
    ecs_vector_t *result =
        ecs_os_malloc(offset + elem_size * elem_count);
    ecs_assert(result != NULL, ECS_OUT_OF_MEMORY, NULL);

    result->count = 0;
    result->size = elem_count;
#ifndef NDEBUG
    result->elem_size = elem_size;
#endif
    return result;
}

ecs_vector_t* _ecs_vector_from_array(
    ecs_size_t elem_size,
    int16_t offset,
    int32_t elem_count,
    void *array)
{
    ecs_assert(elem_size != 0, ECS_INTERNAL_ERROR, NULL);
    
    ecs_vector_t *result =
        ecs_os_malloc(offset + elem_size * elem_count);
    ecs_assert(result != NULL, ECS_OUT_OF_MEMORY, NULL);

    ecs_os_memcpy(ECS_OFFSET(result, offset), array, elem_size * elem_count);

    result->count = elem_count;
    result->size = elem_count;
#ifndef NDEBUG
    result->elem_size = elem_size;
#endif
    return result;   
}

void ecs_vector_free(
    ecs_vector_t *vector)
{
    ecs_os_free(vector);
}

void ecs_vector_clear(
    ecs_vector_t *vector)
{
    if (vector) {
        vector->count = 0;
    }
}

void _ecs_vector_zero(
    ecs_vector_t *vector,
    ecs_size_t elem_size,
    int16_t offset)
{
    void *array = ECS_OFFSET(vector, offset);
    ecs_os_memset(array, 0, elem_size * vector->count);
}

void ecs_vector_assert_size(
    ecs_vector_t *vector,
    ecs_size_t elem_size)
{
    (void)elem_size;
    
    if (vector) {
        ecs_assert(vector->elem_size == elem_size, ECS_INTERNAL_ERROR, NULL);
    }
}

void* _ecs_vector_addn(
    ecs_vector_t **array_inout,
    ecs_size_t elem_size,
    int16_t offset,
    int32_t elem_count)
{
    ecs_assert(array_inout != NULL, ECS_INTERNAL_ERROR, NULL);
    
    if (elem_count == 1) {
        return _ecs_vector_add(array_inout, elem_size, offset);
    }
    
    ecs_vector_t *vector = *array_inout;
    if (!vector) {
        vector = _ecs_vector_new(elem_size, offset, 1);
        *array_inout = vector;
    }

    ecs_assert(vector->elem_size == elem_size, ECS_INTERNAL_ERROR, NULL);

    int32_t max_count = vector->size;
    int32_t old_count = vector->count;
    int32_t new_count = old_count + elem_count;

    if ((new_count - 1) >= max_count) {
        if (!max_count) {
            max_count = elem_count;
        } else {
            while (max_count < new_count) {
                max_count *= 2;
            }
        }

        vector = resize(vector, offset, max_count * elem_size);
        vector->size = max_count;
        *array_inout = vector;
    }

    vector->count = new_count;

    return ECS_OFFSET(vector, offset + elem_size * old_count);
}

void* _ecs_vector_add(
    ecs_vector_t **array_inout,
    ecs_size_t elem_size,
    int16_t offset)
{
    ecs_vector_t *vector = *array_inout;
    int32_t count, size;

    if (vector) {
        ecs_assert(vector->elem_size == elem_size, ECS_INTERNAL_ERROR, NULL);
        count = vector->count;
        size = vector->size;

        if (count >= size) {
            size *= 2;
            if (!size) {
                size = 2;
            }
            vector = resize(vector, offset, size * elem_size);
            *array_inout = vector;
            vector->size = size;
        }

        vector->count = count + 1;
        return ECS_OFFSET(vector, offset + elem_size * count);
    }

    vector = _ecs_vector_new(elem_size, offset, 2);
    *array_inout = vector;
    vector->count = 1;
    vector->size = 2;
    return ECS_OFFSET(vector, offset);
}

int32_t _ecs_vector_move_index(
    ecs_vector_t **dst,
    ecs_vector_t *src,
    ecs_size_t elem_size,
    int16_t offset,
    int32_t index)
{
    ecs_assert((*dst)->elem_size == elem_size, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(src->elem_size == elem_size, ECS_INTERNAL_ERROR, NULL);

    void *dst_elem = _ecs_vector_add(dst, elem_size, offset);
    void *src_elem = _ecs_vector_get(src, elem_size, offset, index);

    ecs_os_memcpy(dst_elem, src_elem, elem_size);
    return _ecs_vector_remove_index(src, elem_size, offset, index);
}

void ecs_vector_remove_last(
    ecs_vector_t *vector)
{
    if (vector && vector->count) vector->count --;
}

bool _ecs_vector_pop(
    ecs_vector_t *vector,
    ecs_size_t elem_size,
    int16_t offset,
    void *value)
{
    if (!vector) {
        return false;
    }

    ecs_assert(vector->elem_size == elem_size, ECS_INTERNAL_ERROR, NULL);

    int32_t count = vector->count;
    if (!count) {
        return false;
    }

    void *elem = ECS_OFFSET(vector, offset + (count - 1) * elem_size);

    if (value) {
        ecs_os_memcpy(value, elem, elem_size);
    }

    ecs_vector_remove_last(vector);

    return true;
}

int32_t _ecs_vector_remove_index(
    ecs_vector_t *vector,
    ecs_size_t elem_size,
    int16_t offset,
    int32_t index)
{
    ecs_assert(vector->elem_size == elem_size, ECS_INTERNAL_ERROR, NULL);
    
    int32_t count = vector->count;
    void *buffer = ECS_OFFSET(vector, offset);
    void *elem = ECS_OFFSET(buffer, index * elem_size);

    ecs_assert(index < count, ECS_INVALID_PARAMETER, NULL);

    count --;
    if (index != count) {
        void *last_elem = ECS_OFFSET(buffer, elem_size * count);
        ecs_os_memcpy(elem, last_elem, elem_size);
    }

    vector->count = count;

    return count;
}

void _ecs_vector_reclaim(
    ecs_vector_t **array_inout,
    ecs_size_t elem_size,
    int16_t offset)
{
    ecs_vector_t *vector = *array_inout;

    ecs_assert(vector->elem_size == elem_size, ECS_INTERNAL_ERROR, NULL);
    
    int32_t size = vector->size;
    int32_t count = vector->count;

    if (count < size) {
        size = count;
        vector = resize(vector, offset, size * elem_size);
        vector->size = size;
        *array_inout = vector;
    }
}

int32_t ecs_vector_count(
    const ecs_vector_t *vector)
{
    if (!vector) {
        return 0;
    }
    return vector->count;
}

int32_t ecs_vector_size(
    const ecs_vector_t *vector)
{
    if (!vector) {
        return 0;
    }
    return vector->size;
}

int32_t _ecs_vector_set_size(
    ecs_vector_t **array_inout,
    ecs_size_t elem_size,
    int16_t offset,
    int32_t elem_count)
{
    ecs_vector_t *vector = *array_inout;

    if (!vector) {
        *array_inout = _ecs_vector_new(elem_size, offset, elem_count);
        return elem_count;
    } else {
        ecs_assert(vector->elem_size == elem_size, ECS_INTERNAL_ERROR, NULL);

        int32_t result = vector->size;

        if (elem_count < vector->count) {
            elem_count = vector->count;
        }

        if (result < elem_count) {
            elem_count = ecs_next_pow_of_2(elem_count);
            vector = resize(vector, offset, elem_count * elem_size);
            vector->size = elem_count;
            *array_inout = vector;
            result = elem_count;
        }

        return result;
    }
}

int32_t _ecs_vector_grow(
    ecs_vector_t **array_inout,
    ecs_size_t elem_size,
    int16_t offset,
    int32_t elem_count)
{
    int32_t current = ecs_vector_count(*array_inout);
    return _ecs_vector_set_size(array_inout, elem_size, offset, current + elem_count);
}

int32_t _ecs_vector_set_count(
    ecs_vector_t **array_inout,
    ecs_size_t elem_size,
    int16_t offset,
    int32_t elem_count)
{
    if (!*array_inout) {
        *array_inout = _ecs_vector_new(elem_size, offset, elem_count);
    }

    ecs_assert((*array_inout)->elem_size == elem_size, ECS_INTERNAL_ERROR, NULL);

    (*array_inout)->count = elem_count;
    ecs_size_t size = _ecs_vector_set_size(array_inout, elem_size, offset, elem_count);
    return size;
}

void* _ecs_vector_first(
    const ecs_vector_t *vector,
    ecs_size_t elem_size,
    int16_t offset)
{
    (void)elem_size;

    ecs_assert(!vector || vector->elem_size == elem_size, ECS_INTERNAL_ERROR, NULL);
    if (vector && vector->size) {
        return ECS_OFFSET(vector, offset);
    } else {
        return NULL;
    }
}

void* _ecs_vector_get(
    const ecs_vector_t *vector,
    ecs_size_t elem_size,
    int16_t offset,
    int32_t index)
{
    if (!vector) {
        return NULL;
    }
    
    ecs_assert(vector->elem_size == elem_size, ECS_INTERNAL_ERROR, NULL);    
    ecs_assert(index >= 0, ECS_INTERNAL_ERROR, NULL);

    int32_t count = vector->count;

    if (index >= count) {
        return NULL;
    }

    return ECS_OFFSET(vector, offset + elem_size * index);
}

void* _ecs_vector_last(
    const ecs_vector_t *vector,
    ecs_size_t elem_size,
    int16_t offset)
{
    if (vector) {
        ecs_assert(vector->elem_size == elem_size, ECS_INTERNAL_ERROR, NULL);
        int32_t count = vector->count;
        if (!count) {
            return NULL;
        } else {
            return ECS_OFFSET(vector, offset + elem_size * (count - 1));
        }
    } else {
        return NULL;
    }
}

int32_t _ecs_vector_set_min_size(
    ecs_vector_t **vector_inout,
    ecs_size_t elem_size,
    int16_t offset,
    int32_t elem_count)
{
    if (!*vector_inout || (*vector_inout)->size < elem_count) {
        return _ecs_vector_set_size(vector_inout, elem_size, offset, elem_count);
    } else {
        return (*vector_inout)->size;
    }
}

int32_t _ecs_vector_set_min_count(
    ecs_vector_t **vector_inout,
    ecs_size_t elem_size,
    int16_t offset,
    int32_t elem_count)
{
    _ecs_vector_set_min_size(vector_inout, elem_size, offset, elem_count);

    ecs_vector_t *v = *vector_inout;
    if (v && v->count < elem_count) {
        v->count = elem_count;
    }

    return v->count;
}

void _ecs_vector_sort(
    ecs_vector_t *vector,
    ecs_size_t elem_size,
    int16_t offset,
    ecs_comparator_t compare_action)
{
    if (!vector) {
        return;
    }

    ecs_assert(vector->elem_size == elem_size, ECS_INTERNAL_ERROR, NULL);    

    int32_t count = vector->count;
    void *buffer = ECS_OFFSET(vector, offset);

    if (count > 1) {
        qsort(buffer, (size_t)count, (size_t)elem_size, compare_action);
    }
}

void _ecs_vector_memory(
    const ecs_vector_t *vector,
    ecs_size_t elem_size,
    int16_t offset,
    int32_t *allocd,
    int32_t *used)
{
    if (!vector) {
        return;
    }

    ecs_assert(vector->elem_size == elem_size, ECS_INTERNAL_ERROR, NULL);

    if (allocd) {
        *allocd += vector->size * elem_size + offset;
    }
    if (used) {
        *used += vector->count * elem_size;
    }
}

ecs_vector_t* _ecs_vector_copy(
    const ecs_vector_t *src,
    ecs_size_t elem_size,
    int16_t offset)
{
    if (!src) {
        return NULL;
    }

    ecs_vector_t *dst = _ecs_vector_new(elem_size, offset, src->size);
    ecs_os_memcpy(dst, src, offset + elem_size * src->count);
    return dst;
}

/** The number of elements in a single chunk */
#define CHUNK_COUNT (4096)

/** Compute the chunk index from an id by stripping the first 12 bits */
#define CHUNK(index) ((int32_t)index >> 12)

/** This computes the offset of an index inside a chunk */
#define OFFSET(index) ((int32_t)index & 0xFFF)

/* Utility to get a pointer to the payload */
#define DATA(array, size, offset) (ECS_OFFSET(array, size * offset))

typedef struct chunk_t {
    int32_t *sparse;            /* Sparse array with indices to dense array */
    void *data;                 /* Store data in sparse array to reduce  
                                 * indirection and provide stable pointers. */
} chunk_t;

struct ecs_sparse_t {
    ecs_vector_t *dense;        /* Dense array with indices to sparse array. The
                                 * dense array stores both alive and not alive
                                 * sparse indices. The 'count' member keeps
                                 * track of which indices are alive. */

    ecs_vector_t *chunks;       /* Chunks with sparse arrays & data */
    ecs_size_t size;            /* Element size */
    int32_t count;              /* Number of alive entries */
    uint64_t max_id_local;      /* Local max index (if no global is set) */
    uint64_t *max_id;           /* Maximum issued sparse index */
};

static
chunk_t* chunk_new(
    ecs_sparse_t *sparse,
    int32_t chunk_index)
{
    int32_t count = ecs_vector_count(sparse->chunks);
    chunk_t *chunks;

    if (count <= chunk_index) {
        ecs_vector_set_count(&sparse->chunks, chunk_t, chunk_index + 1);
        chunks = ecs_vector_first(sparse->chunks, chunk_t);
        ecs_os_memset(&chunks[count], 0, (1 + chunk_index - count) * ECS_SIZEOF(chunk_t));
    } else {
        chunks = ecs_vector_first(sparse->chunks, chunk_t);
    }

    ecs_assert(chunks != NULL, ECS_INTERNAL_ERROR, NULL);

    chunk_t *result = &chunks[chunk_index];
    ecs_assert(result->sparse == NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(result->data == NULL, ECS_INTERNAL_ERROR, NULL);

    /* Initialize sparse array with zero's, as zero is used to indicate that the
     * sparse element has not been paired with a dense element. Use zero
     * as this means we can take advantage of calloc having a possibly better 
     * performance than malloc + memset. */
    result->sparse = ecs_os_calloc(ECS_SIZEOF(int32_t) * CHUNK_COUNT);

    /* Initialize the data array with zero's to guarantee that data is 
     * always initialized. When an entry is removed, data is reset back to
     * zero. Initialize now, as this can take advantage of calloc. */
    result->data = ecs_os_calloc(sparse->size * CHUNK_COUNT);

    ecs_assert(result->sparse != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(result->data != NULL, ECS_INTERNAL_ERROR, NULL);

    return result;
}

static
void chunk_free(
    chunk_t *chunk)
{
    ecs_os_free(chunk->sparse);
    ecs_os_free(chunk->data);
}

static
chunk_t* get_chunk(
    const ecs_sparse_t *sparse,
    int32_t chunk_index)
{
    /* If chunk_index is below zero, application used an invalid entity id */
    ecs_assert(chunk_index >= 0, ECS_INVALID_PARAMETER, NULL);
    chunk_t *result = ecs_vector_get(sparse->chunks, chunk_t, chunk_index);
    if (result && !result->sparse) {
        return NULL;
    }

    return result;
}

static
chunk_t* get_or_create_chunk(
    ecs_sparse_t *sparse,
    int32_t chunk_index)
{
    chunk_t *chunk = get_chunk(sparse, chunk_index);
    if (chunk) {
        return chunk;
    }

    return chunk_new(sparse, chunk_index);
}

static
void grow_dense(
    ecs_sparse_t *sparse)
{
    ecs_vector_add(&sparse->dense, uint64_t);
}

static
uint64_t strip_generation(
    uint64_t *index_out)
{
    uint64_t index = *index_out;
    uint64_t gen = index & ECS_GENERATION_MASK;
    *index_out -= gen;
    return gen;
}

static
void assign_index(
    chunk_t * chunk, 
    uint64_t * dense_array, 
    uint64_t index, 
    int32_t dense)
{
    /* Initialize sparse-dense pair. This assigns the dense index to the sparse
     * array, and the sparse index to the dense array .*/
    chunk->sparse[OFFSET(index)] = dense;
    dense_array[dense] = index;
}

static
uint64_t inc_gen(
    uint64_t index)
{
    /* When an index is deleted, its generation is increased so that we can do
     * liveliness checking while recycling ids */
    return ECS_GENERATION_INC(index);
}

static
uint64_t inc_id(
    ecs_sparse_t *sparse)
{
    /* Generate a new id. The last issued id could be stored in an external
     * variable, such as is the case with the last issued entity id, which is
     * stored on the world. */
    return ++ (sparse->max_id[0]);
}

static
uint64_t get_id(
    const ecs_sparse_t *sparse)
{
    return sparse->max_id[0];
}

static
void set_id(
    ecs_sparse_t *sparse,
    uint64_t value)
{
    /* Sometimes the max id needs to be assigned directly, which typically 
     * happens when the API calls get_or_create for an id that hasn't been 
     * issued before. */
    sparse->max_id[0] = value;
}

/* Pair dense id with new sparse id */
static
uint64_t create_id(
    ecs_sparse_t *sparse,
    int32_t dense)
{
    uint64_t index = inc_id(sparse);
    grow_dense(sparse);

    chunk_t *chunk = get_or_create_chunk(sparse, CHUNK(index));
    ecs_assert(chunk->sparse[OFFSET(index)] == 0, ECS_INTERNAL_ERROR, NULL);
    
    uint64_t *dense_array = ecs_vector_first(sparse->dense, uint64_t);
    assign_index(chunk, dense_array, index, dense);
    
    return index;
}

/* Create new id */
static
uint64_t new_index(
    ecs_sparse_t *sparse)
{
    ecs_vector_t *dense = sparse->dense;
    int32_t dense_count = ecs_vector_count(dense);
    int32_t count = sparse->count ++;

    ecs_assert(count <= dense_count, ECS_INTERNAL_ERROR, NULL);

    if (count < dense_count) {
        /* If there are unused elements in the dense array, return first */
        uint64_t *dense_array = ecs_vector_first(dense, uint64_t);
        return dense_array[count];
    } else {
        return create_id(sparse, count);
    }
}

/* Try obtaining a value from the sparse set, don't care about whether the
 * provided index matches the current generation count.  */
static
void* try_sparse_any(
    const ecs_sparse_t *sparse,
    uint64_t index)
{    
    strip_generation(&index);

    chunk_t *chunk = get_chunk(sparse, CHUNK(index));
    if (!chunk) {
        return NULL;
    }

    int32_t offset = OFFSET(index);
    int32_t dense = chunk->sparse[offset];
    bool in_use = dense && (dense < sparse->count);
    if (!in_use) {
        return NULL;
    }

    ecs_assert(dense == chunk->sparse[offset], ECS_INTERNAL_ERROR, NULL);
    return DATA(chunk->data, sparse->size, offset);
}

/* Try obtaining a value from the sparse set, make sure it's alive. */
static
void* try_sparse(
    const ecs_sparse_t *sparse,
    uint64_t index)
{
    chunk_t *chunk = get_chunk(sparse, CHUNK(index));
    if (!chunk) {
        return NULL;
    }

    int32_t offset = OFFSET(index);
    int32_t dense = chunk->sparse[offset];
    bool in_use = dense && (dense < sparse->count);
    if (!in_use) {
        return NULL;
    }

    uint64_t gen = strip_generation(&index);
    uint64_t *dense_array = ecs_vector_first(sparse->dense, uint64_t);
    uint64_t cur_gen = dense_array[dense] & ECS_GENERATION_MASK;

    if (cur_gen != gen) {
        return NULL;
    }

    ecs_assert(dense == chunk->sparse[offset], ECS_INTERNAL_ERROR, NULL);
    return DATA(chunk->data, sparse->size, offset);
}

/* Get value from sparse set when it is guaranteed that the value exists. This
 * function is used when values are obtained using a dense index */
static
void* get_sparse(
    const ecs_sparse_t *sparse,
    int32_t dense,
    uint64_t index)
{
    strip_generation(&index);
    chunk_t *chunk = get_chunk(sparse, CHUNK(index));
    int32_t offset = OFFSET(index);
    
    ecs_assert(chunk != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(dense == chunk->sparse[offset], ECS_INTERNAL_ERROR, NULL);
    (void)dense;

    return DATA(chunk->data, sparse->size, offset);
}

/* Swap dense elements. A swap occurs when an element is removed, or when a
 * removed element is recycled. */
static
void swap_dense(
    ecs_sparse_t * sparse,
    chunk_t * chunk_a,
    int32_t a,
    int32_t b)
{
    ecs_assert(a != b, ECS_INTERNAL_ERROR, NULL);
    uint64_t *dense_array = ecs_vector_first(sparse->dense, uint64_t);
    uint64_t index_a = dense_array[a];
    uint64_t index_b = dense_array[b];

    chunk_t *chunk_b = get_or_create_chunk(sparse, CHUNK(index_b));
    assign_index(chunk_a, dense_array, index_a, b);
    assign_index(chunk_b, dense_array, index_b, a);
}

ecs_sparse_t* _ecs_sparse_new(
    ecs_size_t size)
{
    ecs_sparse_t *result = ecs_os_calloc(ECS_SIZEOF(ecs_sparse_t));
    ecs_assert(result != NULL, ECS_OUT_OF_MEMORY, NULL);
    result->size = size;
    result->max_id_local = UINT64_MAX;
    result->max_id = &result->max_id_local;

    /* Consume first value in dense array as 0 is used in the sparse array to
     * indicate that a sparse element hasn't been paired yet. */
    uint64_t *first = ecs_vector_add(&result->dense, uint64_t);
    *first = 0;

    result->count = 1;

    return result;
}

void ecs_sparse_set_id_source(
    ecs_sparse_t * sparse,
    uint64_t * id_source)
{
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);
    sparse->max_id = id_source;
}

void ecs_sparse_clear(
    ecs_sparse_t *sparse)
{
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);

    ecs_vector_each(sparse->chunks, chunk_t, chunk, {
        chunk_free(chunk);
    });

    ecs_vector_free(sparse->chunks);
    ecs_vector_set_count(&sparse->dense, uint64_t, 1);

    sparse->chunks = NULL;   
    sparse->count = 1;
    sparse->max_id_local = 0;
}

void ecs_sparse_free(
    ecs_sparse_t *sparse)
{
    if (sparse) {
        ecs_sparse_clear(sparse);
        ecs_vector_free(sparse->dense);
        ecs_os_free(sparse);
    }
}

uint64_t ecs_sparse_new_id(
    ecs_sparse_t *sparse)
{
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);
    return new_index(sparse);
}

const uint64_t* ecs_sparse_new_ids(
    ecs_sparse_t *sparse,
    int32_t new_count)
{
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);
    int32_t dense_count = ecs_vector_count(sparse->dense);
    int32_t count = sparse->count;
    int32_t remaining = dense_count - count;
    int32_t i, to_create = new_count - remaining;

    if (to_create > 0) {
        ecs_sparse_set_size(sparse, dense_count + to_create);
        uint64_t *dense_array = ecs_vector_first(sparse->dense, uint64_t);

        for (i = 0; i < to_create; i ++) {
            uint64_t index = create_id(sparse, count + i);
            dense_array[dense_count + i] = index;
        }
    }

    sparse->count += new_count;

    return ecs_vector_get(sparse->dense, uint64_t, count);
}

void* _ecs_sparse_add(
    ecs_sparse_t *sparse,
    ecs_size_t size)
{
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!size || size == sparse->size, ECS_INVALID_PARAMETER, NULL);
    uint64_t index = new_index(sparse);
    chunk_t *chunk = get_chunk(sparse, CHUNK(index));
    ecs_assert(chunk != NULL, ECS_INTERNAL_ERROR, NULL);
    return DATA(chunk->data, size, OFFSET(index));
}

uint64_t ecs_sparse_last_id(
    ecs_sparse_t *sparse)
{
    ecs_assert(sparse != NULL, ECS_INTERNAL_ERROR, NULL);
    uint64_t *dense_array = ecs_vector_first(sparse->dense, uint64_t);
    return dense_array[sparse->count - 1];
}

void* _ecs_sparse_ensure(
    ecs_sparse_t *sparse,
    ecs_size_t size,
    uint64_t index)
{
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!size || size == sparse->size, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ecs_vector_count(sparse->dense) > 0, ECS_INTERNAL_ERROR, NULL);
    (void)size;

    uint64_t gen = strip_generation(&index);
    chunk_t *chunk = get_or_create_chunk(sparse, CHUNK(index));
    int32_t offset = OFFSET(index);
    int32_t dense = chunk->sparse[offset];

    if (dense) {
        /* Check if element is alive. If element is not alive, update indices so
         * that the first unused dense element points to the sparse element. */
        int32_t count = sparse->count;
        if (dense == count) {
            /* If dense is the next unused element in the array, simply increase
             * the count to make it part of the alive set. */
            sparse->count ++;
        } else if (dense > count) {
            /* If dense is not alive, swap it with the first unused element. */
            swap_dense(sparse, chunk, dense, count);

            /* First unused element is now last used element */
            sparse->count ++;
        } else {
            /* Dense is already alive, nothing to be done */
        }

        /* Ensure provided generation matches current. Only allow mismatching
         * generations if the provided generation count is 0. This allows for
         * using the ensure function in combination with ids that have their
         * generation stripped. */
        ecs_vector_t *dense_vector = sparse->dense;
        uint64_t *dense_array = ecs_vector_first(dense_vector, uint64_t);    
        ecs_assert(!gen || dense_array[dense] == (index | gen), ECS_INTERNAL_ERROR, NULL);
        (void)dense_vector;
        (void)dense_array;
    } else {
        /* Element is not paired yet. Must add a new element to dense array */
        grow_dense(sparse);

        ecs_vector_t *dense_vector = sparse->dense;
        uint64_t *dense_array = ecs_vector_first(dense_vector, uint64_t);    
        int32_t dense_count = ecs_vector_count(dense_vector) - 1;
        int32_t count = sparse->count ++;

        /* If index is larger than max id, update max id */
        if (index >= get_id(sparse)) {
            set_id(sparse, index + 1);
        }

        if (count < dense_count) {
            /* If there are unused elements in the list, move the first unused
             * element to the end of the list */
            uint64_t unused = dense_array[count];
            chunk_t *unused_chunk = get_or_create_chunk(sparse, CHUNK(unused));
            assign_index(unused_chunk, dense_array, unused, dense_count);
        }

        assign_index(chunk, dense_array, index, count);
        dense_array[count] |= gen;
    }

    return DATA(chunk->data, sparse->size, offset);
}

void* _ecs_sparse_set(
    ecs_sparse_t * sparse,
    ecs_size_t elem_size,
    uint64_t index,
    void * value)
{
    void *ptr = _ecs_sparse_ensure(sparse, elem_size, index);
    ecs_os_memcpy(ptr, value, elem_size);
    return ptr;
}

void* _ecs_sparse_remove_get(
    ecs_sparse_t *sparse,
    ecs_size_t size,
    uint64_t index)
{
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!size || size == sparse->size, ECS_INVALID_PARAMETER, NULL);
    (void)size;

    chunk_t *chunk = get_or_create_chunk(sparse, CHUNK(index));
    uint64_t gen = strip_generation(&index);
    int32_t offset = OFFSET(index);
    int32_t dense = chunk->sparse[offset];

    if (dense) {
        uint64_t *dense_array = ecs_vector_first(sparse->dense, uint64_t);
        uint64_t cur_gen = dense_array[dense] & ECS_GENERATION_MASK;
        if (gen != cur_gen) {
            /* Generation doesn't match which means that the provided entity is
             * already not alive. */
            return NULL;
        }

        /* Increase generation */
        dense_array[dense] = index | inc_gen(cur_gen);
        
        int32_t count = sparse->count;
        if (dense == (count - 1)) {
            /* If dense is the last used element, simply decrease count */
            sparse->count --;
        } else if (dense < count) {
            /* If element is alive, move it to unused elements */
            swap_dense(sparse, chunk, dense, count - 1);
            sparse->count --;
        } else {
            /* Element is not alive, nothing to be done */
            return NULL;
        }

        /* Reset memory to zero on remove */
        return DATA(chunk->data, sparse->size, offset);
    } else {
        /* Element is not paired and thus not alive, nothing to be done */
        return NULL;
    }
}

void ecs_sparse_remove(
    ecs_sparse_t *sparse,
    uint64_t index)
{
    void *ptr = _ecs_sparse_remove_get(sparse, 0, index);
    if (ptr) {
        ecs_os_memset(ptr, 0, sparse->size);
    }
}

void ecs_sparse_set_generation(
    ecs_sparse_t *sparse,
    uint64_t index)
{
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);
    chunk_t *chunk = get_or_create_chunk(sparse, CHUNK(index));
    
    uint64_t index_w_gen = index;
    strip_generation(&index);
    int32_t offset = OFFSET(index);
    int32_t dense = chunk->sparse[offset];

    if (dense) {
        /* Increase generation */
        uint64_t *dense_array = ecs_vector_first(sparse->dense, uint64_t);
        dense_array[dense] = index_w_gen;
    } else {
        /* Element is not paired and thus not alive, nothing to be done */
    }
}

bool ecs_sparse_exists(
    const ecs_sparse_t *sparse,
    uint64_t index)
{
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);
    chunk_t *chunk = get_chunk(sparse, CHUNK(index));
    if (!chunk) {
        return false;
    }
    
    strip_generation(&index);
    int32_t offset = OFFSET(index);
    int32_t dense = chunk->sparse[offset];

    return dense != 0;
}

void* _ecs_sparse_get(
    const ecs_sparse_t *sparse,
    ecs_size_t size,
    int32_t dense_index)
{
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!size || size == sparse->size, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(dense_index < sparse->count, ECS_INVALID_PARAMETER, NULL);
    (void)size;

    dense_index ++;

    uint64_t *dense_array = ecs_vector_first(sparse->dense, uint64_t);
    return get_sparse(sparse, dense_index, dense_array[dense_index]);
}

bool ecs_sparse_is_alive(
    const ecs_sparse_t *sparse,
    uint64_t index)
{
    return try_sparse(sparse, index) != NULL;
}

uint64_t ecs_sparse_get_current(
    const ecs_sparse_t *sparse,
    uint64_t index)
{
    chunk_t *chunk = get_chunk(sparse, CHUNK(index));
    if (!chunk) {
        return 0;
    }

    int32_t offset = OFFSET(index);
    int32_t dense = chunk->sparse[offset];
    uint64_t *dense_array = ecs_vector_first(sparse->dense, uint64_t);

    /* If dense is 0 (tombstone) this will return 0 */
    return dense_array[dense];
}

void* _ecs_sparse_get_sparse(
    const ecs_sparse_t *sparse,
    ecs_size_t size,
    uint64_t index)
{
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!size || size == sparse->size, ECS_INVALID_PARAMETER, NULL);
    (void)size;
    return try_sparse(sparse, index);
}

void* _ecs_sparse_get_sparse_any(
    ecs_sparse_t *sparse,
    ecs_size_t size,
    uint64_t index)
{
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!size || size == sparse->size, ECS_INVALID_PARAMETER, NULL);
    (void)size;
    return try_sparse_any(sparse, index);
}

int32_t ecs_sparse_count(
    const ecs_sparse_t *sparse)
{
    if (!sparse) {
        return 0;
    }

    return sparse->count - 1;
}

int32_t ecs_sparse_size(
    const ecs_sparse_t *sparse)
{
    if (!sparse) {
        return 0;
    }
        
    return ecs_vector_count(sparse->dense) - 1;
}

const uint64_t* ecs_sparse_ids(
    const ecs_sparse_t *sparse)
{
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);
    return &(ecs_vector_first(sparse->dense, uint64_t)[1]);
}

void ecs_sparse_set_size(
    ecs_sparse_t *sparse,
    int32_t elem_count)
{
    ecs_assert(sparse != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_vector_set_size(&sparse->dense, uint64_t, elem_count);
}

static
void sparse_copy(
    ecs_sparse_t * dst,
    const ecs_sparse_t * src)
{
    ecs_sparse_set_size(dst, ecs_sparse_size(src));
    const uint64_t *indices = ecs_sparse_ids(src);
    
    ecs_size_t size = src->size;
    int32_t i, count = src->count;

    for (i = 0; i < count - 1; i ++) {
        uint64_t index = indices[i];
        void *src_ptr = _ecs_sparse_get_sparse(src, size, index);
        void *dst_ptr = _ecs_sparse_ensure(dst, size, index);
        ecs_sparse_set_generation(dst, index);
        ecs_os_memcpy(dst_ptr, src_ptr, size);
    }

    set_id(dst, get_id(src));

    ecs_assert(src->count == dst->count, ECS_INTERNAL_ERROR, NULL);
}

ecs_sparse_t* ecs_sparse_copy(
    const ecs_sparse_t *src)
{
    if (!src) {
        return NULL;
    }

    ecs_sparse_t *dst = _ecs_sparse_new(src->size);
    sparse_copy(dst, src);

    return dst;
}

void ecs_sparse_restore(
    ecs_sparse_t * dst,
    const ecs_sparse_t * src)
{
    ecs_assert(dst != NULL, ECS_INVALID_PARAMETER, NULL);
    dst->count = 1;
    if (src) {
        sparse_copy(dst, src);
    }
}

void ecs_sparse_memory(
    ecs_sparse_t *sparse,
    int32_t *allocd,
    int32_t *used)
{
    (void)sparse;
    (void)allocd;
    (void)used;
}

#ifdef FLECS_READER_WRITER


static
void ecs_name_writer_alloc(
    ecs_name_writer_t *writer,
    int32_t len)
{
    writer->len = len;
    if (writer->len > writer->max_len) {
        ecs_os_free(writer->name);
        writer->name = ecs_os_malloc(writer->len);
        writer->max_len = writer->len;
    }
    writer->written = 0;
}

static
bool ecs_name_writer_write(
    ecs_name_writer_t *writer,
    const char *buffer)
{
    ecs_size_t written = writer->len - writer->written;
    char *name_ptr = ECS_OFFSET(writer->name, writer->written);

    ecs_assert(name_ptr != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(buffer != NULL, ECS_INTERNAL_ERROR, NULL);

    if (written >= ECS_SIZEOF(int32_t)) {
        ecs_os_memcpy(name_ptr, buffer, ECS_SIZEOF(int32_t));
        writer->written += ECS_SIZEOF(int32_t);
        return writer->written != writer->len;
    } else {
        ecs_os_memcpy(name_ptr, buffer, written);
        writer->written += written;
        return false;
    }
}

static
void ecs_name_writer_reset(
    ecs_name_writer_t *writer)
{
    writer->name = NULL;
    writer->max_len = 0;
    writer->len = 0;
}

static
void ecs_table_writer_register_table(
    ecs_writer_t *stream)
{
    ecs_world_t *world = stream->world;
    ecs_table_writer_t *writer = &stream->table;
    ecs_type_t type = ecs_type_find(world, writer->type_array, writer->type_count);
    ecs_assert(type != NULL, ECS_INTERNAL_ERROR, NULL);

    writer->table = ecs_table_from_type(world, type);
    ecs_assert(writer->table != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_os_free(writer->type_array);
    writer->type_array = NULL;

    ecs_data_t *data = ecs_table_get_or_create_data(writer->table);
    if (data->entities) {
        /* Remove any existing entities from entity index */
        ecs_vector_each(data->entities, ecs_entity_t, e_ptr, {
            ecs_eis_delete(world, *e_ptr);
            /* Don't increase generation to ensure the restored data exactly
             * matches the data in the blob */
            ecs_eis_set_generation(world, *e_ptr);
        });
      
        return;
    } else {
        /* Set size of table to 0. This will initialize columns */
        ecs_table_set_size(world, writer->table, data, 0);
    }

    ecs_assert(writer->table != NULL, ECS_INTERNAL_ERROR, NULL);
}

static
void ecs_table_writer_finalize_table(
    ecs_writer_t *stream)
{
    ecs_world_t *world = stream->world;
    ecs_table_writer_t *writer = &stream->table;

    /* Register entities in table in entity index */
    ecs_data_t *data = ecs_table_get_data(writer->table);
    ecs_vector_t *entity_vector = data->entities;
    ecs_entity_t *entities = ecs_vector_first(entity_vector, ecs_entity_t);
    ecs_record_t **record_ptrs = ecs_vector_first(data->record_ptrs, ecs_record_t*);
    int32_t i, count = ecs_vector_count(entity_vector);

    for (i = 0; i < count; i ++) {
        ecs_record_t *record_ptr = ecs_eis_get_any(world, entities[i]);

        if (record_ptr) {
            if (record_ptr->table != writer->table) {
                ecs_table_t *table = record_ptr->table;      
                ecs_data_t *table_data = ecs_table_get_data(table);

                ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);
                ecs_table_delete(world, 
                    table, table_data, record_ptr->row - 1, false);
            }
        } else {
            record_ptr = ecs_eis_ensure(world, entities[i]);
        }

        record_ptr->row = i + 1;
        record_ptr->table = writer->table;

        record_ptrs[i] = record_ptr;

        /* Strip entity from generation */
        ecs_entity_t id = entities[i] & ECS_ENTITY_MASK;
        if (id >= world->stats.last_id) {
            world->stats.last_id = id + 1;
        }
        if (id < ECS_HI_COMPONENT_ID) {
            if (id >= world->stats.last_component_id) {
                world->stats.last_component_id = id + 1;
            }
        }
    }
}

static
void ecs_table_writer_prepare_column(
    ecs_writer_t *stream,
    int32_t size)
{
    ecs_table_writer_t *writer = &stream->table;
    ecs_data_t *data = ecs_table_get_or_create_data(writer->table);
        
    ecs_assert(data != NULL, ECS_INTERNAL_ERROR, NULL);

    if (writer->column_index) {
        ecs_column_t *column = &data->columns[writer->column_index - 1];

        if (size) {
            int32_t old_count = ecs_vector_count(column->data);
            _ecs_vector_set_count(&column->data, ECS_VECTOR_U(size, 0), writer->row_count);

            /* Initialize new elements to 0 */
            void *buffer = ecs_vector_first_t(column->data, size, 0);
            ecs_os_memset(ECS_OFFSET(buffer, old_count * size), 0, 
                (writer->row_count - old_count) * size);
        }

        writer->column_vector = column->data;
        writer->column_size = ecs_to_i16(size);
    } else {
        ecs_vector_set_count(
            &data->entities, ecs_entity_t, writer->row_count);

        ecs_vector_set_count(
            &data->record_ptrs, ecs_record_t*, writer->row_count);            

        writer->column_vector = data->entities;
        writer->column_size = ECS_SIZEOF(ecs_entity_t);      
    }

    writer->column_data = ecs_vector_first_t(writer->column_vector,
        writer->column_size, 
        writer->column_alignment);
        
    writer->column_written = 0;
}

static
void ecs_table_writer_next(
    ecs_writer_t *stream)
{
    ecs_table_writer_t *writer = &stream->table;

    switch(writer->state) {
    case EcsTableTypeSize:
        writer->state = EcsTableType;
        break;

    case EcsTableType:
        writer->state = EcsTableSize;
        break;

    case EcsTableSize:
        writer->state = EcsTableColumn;
        break;

    case EcsTableColumnHeader:
        writer->state = EcsTableColumnSize;
        break;

    case EcsTableColumnSize:
        writer->state = EcsTableColumnData;
        break;

    case EcsTableColumnNameHeader:
        writer->state = EcsTableColumnNameLength;
        break;

    case EcsTableColumnNameLength:
        writer->state = EcsTableColumnName;
        break;

    case EcsTableColumnName:
        writer->row_index ++;
        if (writer->row_index < writer->row_count) {
            writer->state = EcsTableColumnNameLength;
            break;
        }
        // fall through

    case EcsTableColumnData:
        writer->column_index ++;

        if (writer->column_index > writer->table->column_count) {
            ecs_table_writer_finalize_table(stream);
            stream->state = EcsStreamHeader;
            writer->column_written = 0;
            writer->state = 0;
            writer->column_index = 0;
            writer->row_index = 0;
        } else {
            writer->state = EcsTableColumn;
        }
        break;

    default:
        ecs_abort(ECS_INTERNAL_ERROR, NULL);
        break;
    }
}

static
ecs_size_t ecs_table_writer(
    const char *buffer,
    ecs_size_t size,
    ecs_writer_t *stream)
{
    ecs_table_writer_t *writer = &stream->table;
    ecs_size_t written = 0;

    ecs_assert(size != 0, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(size >= ECS_SIZEOF(int32_t), ECS_INVALID_PARAMETER, NULL);

    if (!writer->state) {
        writer->state = EcsTableTypeSize;
    }

    switch(writer->state) {
    case EcsTableTypeSize:
        ecs_os_memcpy(&writer->type_count, buffer, ECS_SIZEOF(int32_t));
        writer->type_array = ecs_os_malloc(writer->type_count * ECS_SIZEOF(ecs_entity_t));
        writer->type_max_count = writer->type_count;
        writer->type_written = 0;
        written = ECS_SIZEOF(int32_t);
        ecs_table_writer_next(stream);
        break;

    case EcsTableType:
        ecs_os_memcpy(ECS_OFFSET(writer->type_array, writer->type_written), buffer, ECS_SIZEOF(int32_t));
        written = ECS_SIZEOF(int32_t);
        writer->type_written += written;

        if (writer->type_written == (writer->type_count * ECS_SIZEOF(ecs_entity_t))) {
            ecs_table_writer_register_table(stream);
            ecs_table_writer_next(stream);
        }
        break;

    case EcsTableSize:
        ecs_os_memcpy(&writer->row_count, buffer, ECS_SIZEOF(int32_t));
        written += ECS_SIZEOF(int32_t);
        ecs_table_writer_next(stream);
        break;

    case EcsTableColumn:
        ecs_os_memcpy(&writer->state, buffer, ECS_SIZEOF(ecs_blob_header_kind_t));
        if (writer->state != EcsTableColumnHeader &&
            writer->state != EcsTableColumnNameHeader)
        {
            stream->error = ECS_DESERIALIZE_FORMAT_ERROR;
            goto error;
        }
        written += ECS_SIZEOF(int32_t);
        break;

    case EcsTableColumnHeader:
    case EcsTableColumnSize: {
        int32_t column_size;
        memcpy(&column_size, buffer, ECS_SIZEOF(int32_t));
        ecs_table_writer_prepare_column(stream, column_size);
        ecs_table_writer_next(stream);

        written += ECS_SIZEOF(int32_t);
        ecs_table_writer_next(stream);

        /* If column has no size, there will be no column data, so skip to the
         * next state. */
        if (!writer->column_size) {
            ecs_table_writer_next(stream);
        }
        break;
    }

    case EcsTableColumnData: {
        written = writer->row_count * writer->column_size - writer->column_written;
        if (written > size) {
            written = size;
        }

        ecs_os_memcpy(ECS_OFFSET(writer->column_data, writer->column_written), buffer, written);
        writer->column_written += written;
        written = (((written - 1) / ECS_SIZEOF(int32_t)) + 1) * ECS_SIZEOF(int32_t);

        if (writer->column_written == writer->row_count * writer->column_size) {
            ecs_table_writer_next(stream);
        }
        break;
    }

    case EcsTableColumnNameHeader:
        ecs_table_writer_prepare_column(stream, ECS_SIZEOF(EcsName));
        ecs_table_writer_next(stream);
        // fall through

    case EcsTableColumnNameLength: {
        int32_t name_size;
        memcpy(&name_size, buffer, ECS_SIZEOF(int32_t));
        ecs_name_writer_alloc(&writer->name, name_size);
        written = ECS_SIZEOF(int32_t);
        ecs_table_writer_next(stream);
        break;
    }

    case EcsTableColumnName: {
        written = ECS_SIZEOF(int32_t);
        if (!ecs_name_writer_write(&writer->name, buffer)) {
            EcsName *name_ptr = &((EcsName*)writer->column_data)[writer->row_index];
            name_ptr->value = writer->name.name;

            if (name_ptr->alloc_value) {
                ecs_os_free(name_ptr->alloc_value);
            }

            name_ptr->alloc_value = writer->name.name;

            /* Don't overwrite entity name */
            ecs_name_writer_reset(&writer->name);   

            ecs_table_writer_next(stream);
        }
        break;
    }

    default:
        ecs_abort(ECS_INTERNAL_ERROR, NULL);
        break;
    }

    ecs_assert(written <= size, ECS_INTERNAL_ERROR, NULL);

    return written;
error:
    return -1;
}

int ecs_writer_write(
    const char *buffer,
    int32_t size,
    ecs_writer_t *writer)
{
    int32_t written = 0, total_written = 0, remaining = size;

    if (!size) {
        return 0;
    }

    ecs_assert(size >= ECS_SIZEOF(int32_t), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(size % 4 == 0, ECS_INVALID_PARAMETER, NULL);

    while (total_written < size) {
        if (writer->state == EcsStreamHeader) {
            writer->state = *(ecs_blob_header_kind_t*)ECS_OFFSET(buffer, 
                total_written);

            if (writer->state != EcsTableHeader) {
                writer->error = ECS_DESERIALIZE_FORMAT_ERROR;
                goto error;
            }

            written = ECS_SIZEOF(ecs_blob_header_kind_t);
        } else
        if (writer->state == EcsTableHeader) {
            written = ecs_table_writer(ECS_OFFSET(buffer, total_written), 
                remaining, writer);
        }

        if (!written) {
            break;
        }

        if (written == (ecs_size_t)-1) {
            goto error;
        }

        remaining -= written;
        total_written += written;    
    }

    ecs_assert(total_written <= size, ECS_INTERNAL_ERROR, NULL);

    return total_written == 0;
error:
    return -1;
}

ecs_writer_t ecs_writer_init(
    ecs_world_t *world)
{
    return (ecs_writer_t){
        .world = world,
        .state = EcsStreamHeader,
    };
}

#endif

#ifdef FLECS_DEPRECATED


int32_t ecs_count_w_filter(
    const ecs_world_t *world,
    const ecs_filter_t *filter)
{
    return ecs_count_filter(world, filter);
}

int32_t ecs_count_entity(
    const ecs_world_t *world,
    ecs_id_t entity)
{
    return ecs_count_id(world, entity);
}

void ecs_set_component_actions_w_entity(
    ecs_world_t *world,
    ecs_id_t id,
    EcsComponentLifecycle *actions)
{
    ecs_set_component_actions_w_id(world, id, actions);
}

ecs_entity_t ecs_new_w_entity(
    ecs_world_t *world,
    ecs_id_t id)
{
    return ecs_new_w_id(world, id);
}

const ecs_entity_t* ecs_bulk_new_w_entity(
    ecs_world_t *world,
    ecs_id_t id,
    int32_t count)
{
    return ecs_bulk_new_w_id(world, id, count);
}

void ecs_enable_component_w_entity(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id,
    bool enable)
{
    ecs_enable_component_w_id(world, entity, id, enable);
}

bool ecs_is_component_enabled_w_entity(
    const ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id)
{
    return ecs_is_component_enabled_w_id(world, entity, id);
}

const void* ecs_get_w_entity(
    const ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id)
{
    return ecs_get_w_id(world, entity, id);
}

const void* ecs_get_ref_w_entity(
    const ecs_world_t *world,
    ecs_ref_t *ref,
    ecs_entity_t entity,
    ecs_id_t id)
{
    return ecs_get_ref_w_id(world, ref, entity, id);
}

void* ecs_get_mut_w_entity(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id,
    bool *is_added)
{
    return ecs_get_mut_w_id(world, entity, id, is_added);
}

void ecs_modified_w_entity(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id)
{
    ecs_modified_w_id(world, entity, id);
}

ecs_entity_t ecs_set_ptr_w_entity(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id,
    size_t size,
    const void *ptr)
{
    return ecs_set_ptr_w_id(world, entity, id, size, ptr);
}

bool ecs_has_entity(
    const ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id)
{
    return ecs_has_id(world, entity, id);
}

size_t ecs_entity_str(
    const ecs_world_t *world,
    ecs_id_t entity,
    char *buffer,
    size_t buffer_len)
{
    return ecs_id_str(world, entity, buffer, buffer_len);
}

ecs_entity_t ecs_get_parent_w_entity(
    const ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id)
{
    return ecs_get_object_w_id(world, entity, EcsChildOf, id);
}

int32_t ecs_get_thread_index(
    const ecs_world_t *world)
{
    return ecs_get_stage_id(world);
}

void ecs_add_entity(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id)
{
    ecs_add_id(world, entity, id);
}

void ecs_remove_entity(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_id_t id)
{
    ecs_remove_id(world, entity, id);
}

void ecs_dim_type(
    ecs_world_t *world,
    ecs_type_t type,
    int32_t entity_count)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_PARAMETER, NULL);
    if (type) {
        ecs_table_t *table = ecs_table_from_type(world, type);
        ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);
        
        ecs_data_t *data = ecs_table_get_or_create_data(table);
        ecs_table_set_size(world, table, data, entity_count);
    }
}

ecs_type_t ecs_type_from_entity(
    ecs_world_t *world,
    ecs_entity_t entity)
{
    return ecs_type_from_id(world, entity);
}

ecs_entity_t ecs_type_to_entity(
    const ecs_world_t *world,
    ecs_type_t type)
{
    return ecs_type_to_id(world, type);
}

bool ecs_type_has_entity(
    const ecs_world_t *world,
    ecs_type_t type,
    ecs_entity_t entity)
{
    return ecs_type_has_id(world, type, entity);
}

bool ecs_type_owns_entity(
    const ecs_world_t *world,
    ecs_type_t type,
    ecs_entity_t entity,
    bool owned)
{
    return ecs_type_owns_id(world, type, entity, owned);
}

ecs_type_t ecs_column_type(
    const ecs_iter_t *it,
    int32_t index)
{
    ecs_assert(index <= it->column_count, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(index > 0, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(it->table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(it->table->types != NULL, ECS_INTERNAL_ERROR, NULL);
    return it->table->types[index - 1];
}

int32_t ecs_column_index_from_name(
    const ecs_iter_t *it,
    const char *name)
{
    if (it->query) {
        ecs_term_t *terms = it->query->filter.terms;
        int32_t i, count = it->query->filter.term_count;

        for (i = 0; i < count; i ++) {
            ecs_term_t *term = &terms[i];
            if (term->name) {
                if (!strcmp(name, term->name)) {
                    return i + 1;
                }
            }
        }
    }

    return 0;
}

void* ecs_column_w_size(
    const ecs_iter_t *it,
    size_t size,
    int32_t column)
{
    return ecs_term_w_size(it, size, column);
}

bool ecs_is_owned(
    const ecs_iter_t *it,
    int32_t column)
{
    return ecs_term_is_owned(it, column);
}

bool ecs_is_readonly(
    const ecs_iter_t *it,
    int32_t column)
{
    return ecs_term_is_readonly(it, column);
}

ecs_entity_t ecs_column_source(
    const ecs_iter_t *it,
    int32_t index)
{
    return ecs_term_source(it, index);
}

ecs_id_t ecs_column_entity(
    const ecs_iter_t *it,
    int32_t index)
{
    return ecs_term_id(it, index);
}

size_t ecs_column_size(
    const ecs_iter_t *it,
    int32_t index)
{
    return ecs_term_size(it, index);
}

int32_t ecs_table_component_index(
    const ecs_iter_t *it,
    ecs_entity_t component)
{
    return ecs_iter_find_column(it, component);
}

void* ecs_table_column(
    const ecs_iter_t *it,
    int32_t column_index)
{
    return ecs_iter_column_w_size(it, 0, column_index);
}

size_t ecs_table_column_size(
    const ecs_iter_t *it,
    int32_t column_index)
{
    return ecs_iter_column_size(it, column_index);
}

ecs_query_t* ecs_query_new(
    ecs_world_t *world,
    const char *expr)
{
    return ecs_query_init(world, &(ecs_query_desc_t){
        .filter.expr = expr
    });
}

void ecs_query_free(
    ecs_query_t *query)
{
    ecs_query_fini(query);
}

ecs_query_t* ecs_subquery_new(
    ecs_world_t *world,
    ecs_query_t *parent,
    const char *expr)
{
    return ecs_query_init(world, &(ecs_query_desc_t){
        .filter.expr = expr,
        .parent = parent
    });
}

#endif

#ifdef FLECS_MODULE


char* ecs_module_path_from_c(
    const char *c_name)
{
    ecs_strbuf_t str = ECS_STRBUF_INIT;
    const char *ptr;
    char ch;

    for (ptr = c_name; (ch = *ptr); ptr++) {
        if (isupper(ch)) {
            ch = ecs_to_i8(tolower(ch));
            if (ptr != c_name) {
                ecs_strbuf_appendstrn(&str, ".", 1);
            }
        }

        ecs_strbuf_appendstrn(&str, &ch, 1);
    }

    return ecs_strbuf_get(&str);
}

ecs_entity_t ecs_import(
    ecs_world_t *world,
    ecs_module_action_t init_action,
    const char *module_name,
    void *handles_out,
    size_t handles_size)
{
    ecs_assert(!world->is_readonly, ECS_INVALID_WHILE_ITERATING, NULL);

    ecs_entity_t old_scope = ecs_set_scope(world, 0);
    const char *old_name_prefix = world->name_prefix;

    char *path = ecs_module_path_from_c(module_name);
    ecs_entity_t e = ecs_lookup_fullpath(world, path);
    ecs_os_free(path);
    
    if (!e) {
        ecs_trace_1("import %s", module_name);
        ecs_log_push();

        /* Load module */
        init_action(world);

        /* Lookup module entity (must be registered by module) */
        e = ecs_lookup_fullpath(world, module_name);
        ecs_assert(e != 0, ECS_MODULE_UNDEFINED, module_name);

        ecs_log_pop();
    }

    /* Copy value of module component in handles_out parameter */
    if (handles_size && handles_out) {
        void *handles_ptr = ecs_get_mut_w_id(world, e, e, NULL);
        ecs_os_memcpy(handles_out, handles_ptr, ecs_from_size_t(handles_size));   
    }

    /* Restore to previous state */
    ecs_set_scope(world, old_scope);
    world->name_prefix = old_name_prefix;

    return e;
}

ecs_entity_t ecs_import_from_library(
    ecs_world_t *world,
    const char *library_name,
    const char *module_name)
{
    ecs_assert(library_name != NULL, ECS_INVALID_PARAMETER, NULL);

    char *import_func = (char*)module_name; /* safe */
    char *module = (char*)module_name;

    if (!ecs_os_has_modules() || !ecs_os_has_dl()) {
        ecs_os_err(
            "library loading not supported, set module_to_dl, dlopen, dlclose "
            "and dlproc os API callbacks first");
        return 0;
    }

    /* If no module name is specified, try default naming convention for loading
     * the main module from the library */
    if (!import_func) {
        import_func = ecs_os_malloc(ecs_os_strlen(library_name) + ECS_SIZEOF("Import"));
        ecs_assert(import_func != NULL, ECS_OUT_OF_MEMORY, NULL);
        
        const char *ptr;
        char ch, *bptr = import_func;
        bool capitalize = true;
        for (ptr = library_name; (ch = *ptr); ptr ++) {
            if (ch == '.') {
                capitalize = true;
            } else {
                if (capitalize) {
                    *bptr = ecs_to_i8(toupper(ch));
                    bptr ++;
                    capitalize = false;
                } else {
                    *bptr = ecs_to_i8(tolower(ch));
                    bptr ++;
                }
            }
        }

        *bptr = '\0';

        module = ecs_os_strdup(import_func);
        ecs_assert(module != NULL, ECS_OUT_OF_MEMORY, NULL);

        ecs_os_strcat(bptr, "Import");
    }

    char *library_filename = ecs_os_module_to_dl(library_name);
    if (!library_filename) {
        ecs_os_err("failed to find library file for '%s'", library_name);
        if (module != module_name) {
            ecs_os_free(module);
        }
        return 0;
    } else {
        ecs_trace_1("found file '%s' for library '%s'", 
            library_filename, library_name);
    }

    ecs_os_dl_t dl = ecs_os_dlopen(library_filename);
    if (!dl) {
        ecs_os_err("failed to load library '%s' ('%s')", 
            library_name, library_filename);
        
        ecs_os_free(library_filename);

        if (module != module_name) {
            ecs_os_free(module);
        }    

        return 0;
    } else {
        ecs_trace_1("library '%s' ('%s') loaded", 
            library_name, library_filename);
    }

    ecs_module_action_t action = (ecs_module_action_t)
        ecs_os_dlproc(dl, import_func);
    if (!action) {
        ecs_os_err("failed to load import function %s from library %s",
            import_func, library_name);
        ecs_os_free(library_filename);
        ecs_os_dlclose(dl);            
        return 0;
    } else {
        ecs_trace_1("found import function '%s' in library '%s' for module '%s'",
            import_func, library_name, module);
    }

    /* Do not free id, as it will be stored as the component identifier */
    ecs_entity_t result = ecs_import(world, action, module, NULL, 0);

    if (import_func != module_name) {
        ecs_os_free(import_func);
    }

    if (module != module_name) {
        ecs_os_free(module);
    }

    ecs_os_free(library_filename);

    return result;
}

ecs_entity_t ecs_new_module(
    ecs_world_t *world,
    ecs_entity_t e,
    const char *name,
    size_t size,
    size_t alignment)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_PARAMETER, NULL);

    if (!e) {
        char *module_path = ecs_module_path_from_c(name);
        e = ecs_new_from_fullpath(world, module_path);

        EcsName *name_ptr = ecs_get_mut(world, e, EcsName, NULL);
        ecs_os_free(name_ptr->symbol);

        /* Assign full path to symbol. This allows for modules to be redefined
         * in C++ without causing name conflicts */
        name_ptr->symbol = module_path;
    }

    ecs_entity_t result = ecs_component_init(world, &(ecs_component_desc_t){
        .entity = {
            .entity = e
        },
        .size = size,
        .alignment = alignment
    });
    
    ecs_assert(result != 0, ECS_INTERNAL_ERROR, NULL);

    /* Add module tag */
    ecs_add_id(world, result, EcsModule);

    /* Add module to itself. This way we have all the module information stored
     * in a single contained entity that we can use for namespacing */
    ecs_set_ptr_w_id(world, result, result, size, NULL);

    /* Set the current scope to the module */
    ecs_set_scope(world, result);

    return result;
}

#endif

#ifdef FLECS_QUEUE

struct ecs_queue_t {
    ecs_vector_t *data;
    int32_t index;
};

ecs_queue_t* _ecs_queue_new(
    ecs_size_t elem_size,
    int16_t offset,
    int32_t elem_count)
{
    ecs_queue_t *result = ecs_os_malloc(ECS_SIZEOF(ecs_queue_t));
    ecs_assert(result != NULL, ECS_OUT_OF_MEMORY, NULL);

    result->data = _ecs_vector_new(elem_size, offset, elem_count);
    result->index = 0;
    return result;
}

ecs_queue_t* _ecs_queue_from_array(
    ecs_size_t elem_size,
    int16_t offset,
    int32_t elem_count,
    void *array)
{
    ecs_queue_t *result = ecs_os_malloc(ECS_SIZEOF(ecs_queue_t));
    ecs_assert(result != NULL, ECS_OUT_OF_MEMORY, NULL);

    result->data = _ecs_vector_from_array(elem_size, offset, elem_count, array);
    result->index = 0;
    return result;    
}

void* _ecs_queue_push(
    ecs_queue_t *buffer,
    ecs_size_t elem_size,
    int16_t offset)
{
    int32_t size = ecs_vector_size(buffer->data);
    int32_t count = ecs_vector_count(buffer->data);
    void *result;

    if (count == buffer->index) {
        result = _ecs_vector_add(&buffer->data, elem_size, offset);
    } else {
        result = _ecs_vector_get(buffer->data, elem_size, offset, buffer->index);
    }

    buffer->index = (buffer->index + 1) % size;

    return result;
}

void ecs_queue_free(
    ecs_queue_t *buffer)
{
    ecs_vector_free(buffer->data);
    ecs_os_free(buffer);
}

void* _ecs_queue_get(
    ecs_queue_t *buffer,
    ecs_size_t elem_size,
    int16_t offset,
    int32_t index)
{
    int32_t count = ecs_vector_count(buffer->data);
    int32_t size = ecs_vector_size(buffer->data);
    index = ((buffer->index - count + size) + (int32_t)index) % size;
    return _ecs_vector_get(buffer->data, elem_size, offset, index);
}

void* _ecs_queue_last(
    ecs_queue_t *buffer,
    ecs_size_t elem_size,
    int16_t offset)
{
    int32_t index = buffer->index;
    if (!index) {
        index = ecs_vector_size(buffer->data);
    }

    return _ecs_vector_get(buffer->data, elem_size, offset, index - 1);
}

int32_t ecs_queue_index(
    ecs_queue_t *buffer)
{
    return buffer->index;
}

int32_t ecs_queue_count(
    ecs_queue_t *buffer)
{
    return ecs_vector_count(buffer->data);
}

#endif


#ifdef FLECS_STATS

#ifdef FLECS_SYSTEM
#ifndef FLECS_SYSTEM_PRIVATE_H
#define FLECS_SYSTEM_PRIVATE_H


typedef struct EcsSystem {
    ecs_iter_action_t action;       /* Callback to be invoked for matching it */
    void *ctx;                      /* Userdata for system */

    ecs_entity_t entity;                  /* Entity id of system, used for ordering */
    ecs_query_t *query;                   /* System query */
    ecs_on_demand_out_t *on_demand;       /* Keep track of [out] column refs */
    ecs_system_status_action_t status_action; /* Status action */
    void *status_ctx;                     /* User data for status action */    
    ecs_entity_t tick_source;             /* Tick source associated with system */
    
    int32_t invoke_count;                 /* Number of times system is invoked */
    FLECS_FLOAT time_spent;               /* Time spent on running system */
    FLECS_FLOAT time_passed;              /* Time passed since last invocation */
} EcsSystem;

/* Invoked when system becomes active / inactive */
void ecs_system_activate(
    ecs_world_t *world,
    ecs_entity_t system,
    bool activate,
    const EcsSystem *system_data);

/* Internal function to run a system */
ecs_entity_t ecs_run_intern(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t system,
    EcsSystem *system_data,
    int32_t stage_current,
    int32_t stage_count,
    FLECS_FLOAT delta_time,
    int32_t offset,
    int32_t limit,
    const ecs_filter_t *filter,
    void *param);

#endif
#endif

#ifdef FLECS_PIPELINE
#ifndef FLECS_PIPELINE_PRIVATE_H
#define FLECS_PIPELINE_PRIVATE_H


/** Instruction data for pipeline.
 * This type is the element type in the "ops" vector of a pipeline and contains
 * information about the set of systems that need to be ran before a merge. */
typedef struct ecs_pipeline_op_t {
    int32_t count;              /**< Number of systems to run before merge */
} ecs_pipeline_op_t;

typedef struct EcsPipelineQuery {
    ecs_query_t *query;
    ecs_query_t *build_query;
    int32_t match_count;
    ecs_vector_t *ops;
} EcsPipelineQuery;

////////////////////////////////////////////////////////////////////////////////
//// Pipeline API
////////////////////////////////////////////////////////////////////////////////

/** Update a pipeline (internal function).
 * Before running a pipeline, it must be updated. During this update phase
 * all systems in the pipeline are collected, ordered and sync points are 
 * inserted where necessary. This operation may only be called when staging is
 * disabled.
 *
 * Because multiple threads may run a pipeline, preparing the pipeline must 
 * happen synchronously, which is why this function is separate from 
 * ecs_pipeline_run. Not running the prepare step may cause systems to not get
 * ran, or ran in the wrong order.
 *
 * If 0 is provided for the pipeline id, the default pipeline will be ran (this
 * is either the builtin pipeline or the pipeline set with set_pipeline()).
 * 
 * @param world The world.
 * @param pipeline The pipeline to run.
 * @return The number of elements in the pipeline.
 */
int32_t ecs_pipeline_update(
    ecs_world_t *world,
    ecs_entity_t pipeline,
    bool start_of_frame); 

////////////////////////////////////////////////////////////////////////////////
//// Worker API
////////////////////////////////////////////////////////////////////////////////

void ecs_worker_begin(
    ecs_world_t *world);

bool ecs_worker_sync(
    ecs_world_t *world);

void ecs_worker_end(
    ecs_world_t *world);

void ecs_workers_progress(
    ecs_world_t *world,
    ecs_entity_t pipeline,
    FLECS_FLOAT delta_time);

#endif
#endif

static
int32_t t_next(
    int32_t t)
{
    return (t + 1) % ECS_STAT_WINDOW;
}

static
int32_t t_prev(
    int32_t t)
{
    return (t - 1 + ECS_STAT_WINDOW) % ECS_STAT_WINDOW;
}

static
void _record_gauge(
    ecs_gauge_t *m,
    int32_t t,
    float value)
{
    m->avg[t] = value;
    m->min[t] = value;
    m->max[t] = value;
}

static
float _record_counter(
    ecs_counter_t *m,
    int32_t t,
    float value)
{
    int32_t tp = t_prev(t);
    float prev = m->value[tp];
    m->value[t] = value;
    _record_gauge((ecs_gauge_t*)m, t, value - prev);
    return value - prev;
}

/* Macro's to silence conversion warnings without adding casts everywhere */
#define record_gauge(m, t, value)\
    _record_gauge(m, t, (float)value)

#define record_counter(m, t, value)\
    _record_counter(m, t, (float)value)

static
void print_value(
    const char *name,
    float value)
{
    ecs_size_t len = ecs_os_strlen(name);
    printf("%s: %*s %.2f\n", name, 32 - len, "", (double)value);
}

static
void print_gauge(
    const char *name,
    int32_t t,
    const ecs_gauge_t *m)
{
    print_value(name, m->avg[t]);
}

static
void print_counter(
    const char *name,
    int32_t t,
    const ecs_counter_t *m)
{
    print_value(name, m->rate.avg[t]);
}

void ecs_gauge_reduce(
    ecs_gauge_t *dst,
    int32_t t_dst,
    ecs_gauge_t *src,
    int32_t t_src)
{
    ecs_assert(dst != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(src != NULL, ECS_INVALID_PARAMETER, NULL);

    bool min_set = false;
    dst->min[t_dst] = 0;
    dst->avg[t_dst] = 0;
    dst->max[t_dst] = 0;

    int32_t i;
    for (i = 0; i < ECS_STAT_WINDOW; i ++) {
        int32_t t = (t_src + i) % ECS_STAT_WINDOW;
        dst->avg[t_dst] += src->avg[t] / (float)ECS_STAT_WINDOW;
        if (!min_set || (src->min[t] < dst->min[t_dst])) {
            dst->min[t_dst] = src->min[t];
            min_set = true;
        }
        if ((src->max[t] > dst->max[t_dst])) {
            dst->max[t_dst] = src->max[t];
        }
    }
}

void ecs_get_world_stats(
    const ecs_world_t *world,
    ecs_world_stats_t *s)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(s != NULL, ECS_INVALID_PARAMETER, NULL);

    world = ecs_get_world(world);

    int32_t t = s->t = t_next(s->t);

    float delta_world_time = record_counter(&s->world_time_total_raw, t, world->stats.world_time_total_raw);
    record_counter(&s->world_time_total, t, world->stats.world_time_total);
    record_counter(&s->frame_time_total, t, world->stats.frame_time_total);
    record_counter(&s->system_time_total, t, world->stats.system_time_total);
    record_counter(&s->merge_time_total, t, world->stats.merge_time_total);

    float delta_frame_count = record_counter(&s->frame_count_total, t, world->stats.frame_count_total);
    record_counter(&s->merge_count_total, t, world->stats.merge_count_total);
    record_counter(&s->pipeline_build_count_total, t, world->stats.pipeline_build_count_total);
    record_counter(&s->systems_ran_frame, t, world->stats.systems_ran_frame);

    if (delta_world_time != 0.0f && delta_frame_count != 0.0f) {
        record_gauge(
            &s->fps, t, 1.0f / (delta_world_time / (float)delta_frame_count));
    } else {
        record_gauge(&s->fps, t, 0);
    }

    record_gauge(&s->entity_count, t, ecs_sparse_count(world->store.entity_index));
    record_gauge(&s->component_count, t, ecs_count_id(world, ecs_id(EcsComponent)));
    record_gauge(&s->query_count, t, ecs_sparse_count(world->queries));
    record_gauge(&s->system_count, t, ecs_count_id(world, ecs_id(EcsSystem)));

    record_counter(&s->new_count, t, world->new_count);
    record_counter(&s->bulk_new_count, t, world->bulk_new_count);
    record_counter(&s->delete_count, t, world->delete_count);
    record_counter(&s->clear_count, t, world->clear_count);
    record_counter(&s->add_count, t, world->add_count);
    record_counter(&s->remove_count, t, world->remove_count);
    record_counter(&s->set_count, t, world->set_count);
    record_counter(&s->discard_count, t, world->discard_count);

    /* Compute table statistics */
    int32_t empty_table_count = 0;
    int32_t singleton_table_count = 0;
    int32_t matched_table_count = 0, matched_entity_count = 0;

    int32_t i, count = ecs_sparse_count(world->store.tables);
    for (i = 0; i < count; i ++) {
        ecs_table_t *table = ecs_sparse_get(world->store.tables, ecs_table_t, i);
        int32_t entity_count = ecs_table_count(table);

        if (!entity_count) {
            empty_table_count ++;
        }

        /* Singleton tables are tables that have just one entity that also has
         * itself in the table type. */
        if (entity_count == 1) {
            ecs_data_t *data = ecs_table_get_data(table);
            ecs_entity_t *entities = ecs_vector_first(data->entities, ecs_entity_t);
            if (ecs_type_has_id(world, table->type, entities[0])) {
                singleton_table_count ++;
            }
        }

        /* If this table matches with queries and is not empty, increase the
         * matched table & matched entity count. These statistics can be used to
         * compute actual fragmentation ratio for queries. */
        int32_t queries_matched = ecs_vector_count(table->queries);
        if (queries_matched && entity_count) {
            matched_table_count ++;
            matched_entity_count += entity_count;
        }
    }

    record_gauge(&s->matched_table_count, t, matched_table_count);
    record_gauge(&s->matched_entity_count, t, matched_entity_count);
    
    record_gauge(&s->table_count, t, count);
    record_gauge(&s->empty_table_count, t, empty_table_count);
    record_gauge(&s->singleton_table_count, t, singleton_table_count);
}

void ecs_get_query_stats(
    const ecs_world_t *world,
    const ecs_query_t *query,
    ecs_query_stats_t *s)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(query != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(s != NULL, ECS_INVALID_PARAMETER, NULL);
    (void)world;

    world = ecs_get_world(world);

    int32_t t = s->t = t_next(s->t);

    int32_t i, entity_count = 0, count = ecs_vector_count(query->tables);
    ecs_matched_table_t *matched_tables = ecs_vector_first(
        query->tables, ecs_matched_table_t);
    for (i = 0; i < count; i ++) {
        ecs_matched_table_t *matched = &matched_tables[i];
        if (matched->iter_data.table) {
            entity_count += ecs_table_count(matched->iter_data.table);
        }
    }

    record_gauge(&s->matched_table_count, t, count);
    record_gauge(&s->matched_empty_table_count, t, 
        ecs_vector_count(query->empty_tables));
    record_gauge(&s->matched_entity_count, t, entity_count);
}

#ifdef FLECS_SYSTEM
bool ecs_get_system_stats(
    const ecs_world_t *world,
    ecs_entity_t system,
    ecs_system_stats_t *s)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(s != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(system != 0, ECS_INVALID_PARAMETER, NULL);

    world = ecs_get_world(world);

    const EcsSystem *ptr = ecs_get(world, system, EcsSystem);
    if (!ptr) {
        return false;
    }

    ecs_get_query_stats(world, ptr->query, &s->query_stats);
    int32_t t = s->query_stats.t;

    record_counter(&s->time_spent, t, ptr->time_spent);
    record_counter(&s->invoke_count, t, ptr->invoke_count);
    record_gauge(&s->active, t, !ecs_has_id(world, system, EcsInactive));
    record_gauge(&s->enabled, t, !ecs_has_id(world, system, EcsDisabled));

    return true;
}
#endif


#ifdef FLECS_PIPELINE

static ecs_system_stats_t* get_system_stats(
    ecs_map_t *systems,
    ecs_entity_t system)
{
    ecs_assert(systems != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(system != 0, ECS_INVALID_PARAMETER, NULL);

    ecs_system_stats_t *s = ecs_map_get(systems, ecs_system_stats_t, system);
    if (!s) {
        ecs_system_stats_t stats;
        memset(&stats, 0, sizeof(ecs_system_stats_t));
        ecs_map_set(systems, system, &stats);
        s = ecs_map_get(systems, ecs_system_stats_t, system);
        ecs_assert(s != NULL, ECS_INTERNAL_ERROR, NULL);
    }

    return s;
}

bool ecs_get_pipeline_stats(
    const ecs_world_t *world,
    ecs_entity_t pipeline,
    ecs_pipeline_stats_t *s)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(s != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(pipeline != 0, ECS_INVALID_PARAMETER, NULL);

    world = ecs_get_world(world);

    const EcsPipelineQuery *pq = ecs_get(world, pipeline, EcsPipelineQuery);
    if (!pq) {
        return false;
    }

    /* First find out how many systems are matched by the pipeline */
    ecs_iter_t it = ecs_query_iter(pq->query);
    int32_t count = 0;
    while (ecs_query_next(&it)) {
        count += it.count;
    }

    if (!s->system_stats) {
        s->system_stats = ecs_map_new(ecs_system_stats_t, count);
    }    

    /* Also count synchronization points */
    ecs_vector_t *ops = pq->ops;
    ecs_pipeline_op_t *op = ecs_vector_first(ops, ecs_pipeline_op_t);
    ecs_pipeline_op_t *op_last = ecs_vector_last(ops, ecs_pipeline_op_t);
    count += ecs_vector_count(ops);

    /* Make sure vector is large enough to store all systems & sync points */
    ecs_vector_set_count(&s->systems, ecs_entity_t, count - 1);
    ecs_entity_t *systems = ecs_vector_first(s->systems, ecs_entity_t);

    /* Populate systems vector, keep track of sync points */
    it = ecs_query_iter(pq->query);
    int32_t i_system = 0, ran_since_merge = 0;
    while (ecs_query_next(&it)) {
        int32_t i;
        for (i = 0; i < it.count; i ++) {
            systems[i_system ++] = it.entities[i];
            ran_since_merge ++;
            if (op != op_last && ran_since_merge == op->count) {
                ran_since_merge = 0;
                op++;
                systems[i_system ++] = 0; /* 0 indicates a merge point */
            }

            ecs_system_stats_t *sys_stats = get_system_stats(
                s->system_stats, it.entities[i]);
            ecs_get_system_stats(world, it.entities[i], sys_stats);
        }
    }

    ecs_assert(i_system == (count - 1), ECS_INTERNAL_ERROR, NULL);

    return true;
}
#endif

void ecs_dump_world_stats(
    const ecs_world_t *world,
    const ecs_world_stats_t *s)
{
    int32_t t = s->t;

    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(s != NULL, ECS_INVALID_PARAMETER, NULL);

    world = ecs_get_world(world);    
    
    print_counter("Frame", t, &s->frame_count_total);
    printf("-------------------------------------\n");
    print_counter("pipeline rebuilds", t, &s->pipeline_build_count_total);
    print_counter("systems ran last frame", t, &s->systems_ran_frame);
    printf("\n");
    print_value("target FPS", world->stats.target_fps);
    print_value("time scale", world->stats.time_scale);
    printf("\n");
    print_gauge("actual FPS", t, &s->fps);
    print_counter("frame time", t, &s->frame_time_total);
    print_counter("system time", t, &s->system_time_total);
    print_counter("merge time", t, &s->merge_time_total);
    print_counter("simulation time elapsed", t, &s->world_time_total);
    printf("\n");
    print_gauge("entity count", t, &s->entity_count);
    print_gauge("component count", t, &s->component_count);
    print_gauge("query count", t, &s->query_count);
    print_gauge("system count", t, &s->system_count);
    print_gauge("table count", t, &s->table_count);
    print_gauge("singleton table count", t, &s->singleton_table_count);
    print_gauge("empty table count", t, &s->empty_table_count);
    printf("\n");
    print_counter("deferred new operations", t, &s->new_count);
    print_counter("deferred bulk_new operations", t, &s->bulk_new_count);
    print_counter("deferred delete operations", t, &s->delete_count);
    print_counter("deferred clear operations", t, &s->clear_count);
    print_counter("deferred add operations", t, &s->add_count);
    print_counter("deferred remove operations", t, &s->remove_count);
    print_counter("deferred set operations", t, &s->set_count);
    print_counter("discarded operations", t, &s->discard_count);
    printf("\n");
}

#endif

#ifdef FLECS_SNAPSHOT


/* World snapshot */
struct ecs_snapshot_t {
    ecs_world_t *world;
    ecs_sparse_t *entity_index;
    ecs_vector_t *tables;
    ecs_entity_t last_id;
    ecs_filter_t filter;
};

static
ecs_data_t* duplicate_data(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *main_data)
{
    ecs_data_t *result = ecs_os_calloc(ECS_SIZEOF(ecs_data_t));

    int32_t i, column_count = table->column_count;
    ecs_entity_t *components = ecs_vector_first(table->type, ecs_entity_t);

    result->columns = ecs_os_memdup(
        main_data->columns, ECS_SIZEOF(ecs_column_t) * column_count);

    /* Copy entities */
    result->entities = ecs_vector_copy(main_data->entities, ecs_entity_t);
    ecs_entity_t *entities = ecs_vector_first(result->entities, ecs_entity_t);

    /* Copy record ptrs */
    result->record_ptrs = ecs_vector_copy(main_data->record_ptrs, ecs_record_t*);

    /* Copy each column */
    for (i = 0; i < column_count; i ++) {
        ecs_entity_t component = components[i];
        ecs_column_t *column = &result->columns[i];

        if (component > ECS_HI_COMPONENT_ID) {
            column->data = NULL;
            continue;
        }

        const ecs_type_info_t *cdata = ecs_get_c_info(world, component);
        int16_t size = column->size;
        int16_t alignment = column->alignment;
        ecs_copy_t copy;

        if (cdata && (copy = cdata->lifecycle.copy)) {
            int32_t count = ecs_vector_count(column->data);
            ecs_vector_t *dst_vec = ecs_vector_new_t(size, alignment, count);
            ecs_vector_set_count_t(&dst_vec, size, alignment, count);
            void *dst_ptr = ecs_vector_first_t(dst_vec, size, alignment);
            void *ctx = cdata->lifecycle.ctx;
            
            ecs_xtor_t ctor = cdata->lifecycle.ctor;
            if (ctor) {
                ctor(world, component, entities, dst_ptr, ecs_to_size_t(size), 
                    count, ctx);
            }

            void *src_ptr = ecs_vector_first_t(column->data, size, alignment);
            copy(world, component, entities, entities, dst_ptr, src_ptr, 
                ecs_to_size_t(size), count, ctx);

            column->data = dst_vec;
        } else {
            column->data = ecs_vector_copy_t(column->data, size, alignment);
        }
    }

    return result;
}

static
ecs_snapshot_t* snapshot_create(
    ecs_world_t *world,
    const ecs_sparse_t *entity_index,
    ecs_iter_t *iter,
    ecs_iter_next_action_t next)
{
    ecs_snapshot_t *result = ecs_os_calloc(ECS_SIZEOF(ecs_snapshot_t));
    ecs_assert(result != NULL, ECS_OUT_OF_MEMORY, NULL);

    result->world = world;

    /* If no iterator is provided, the snapshot will be taken of the entire
     * world, and we can simply copy the entity index as it will be restored
     * entirely upon snapshote restore. */
    if (!iter && entity_index) {
        result->entity_index = ecs_sparse_copy(entity_index);
        result->tables = ecs_vector_new(ecs_table_leaf_t, 0);
    }

    ecs_iter_t iter_stack;
    if (!iter) {
        iter_stack = ecs_filter_iter(world, NULL);
        iter = &iter_stack;
        next = ecs_filter_next;
    }

    /* If an iterator is provided, this is a filterred snapshot. In this case we
     * have to patch the entity index one by one upon restore, as we don't want
     * to affect entities that were not part of the snapshot. */
    else {
        result->entity_index = NULL;
    }

    /* Iterate tables in iterator */
    while (next(iter)) {
        ecs_table_t *t = iter->table->table;

        if (t->flags & EcsTableHasBuiltins) {
            continue;
        }

        ecs_data_t *data = ecs_table_get_data(t);
        if (!data || !data->entities || !ecs_vector_count(data->entities)) {
            continue;
        }

        ecs_table_leaf_t *l = ecs_vector_add(&result->tables, ecs_table_leaf_t);

        l->table = t;
        l->type = t->type;
        l->data = duplicate_data(world, t, data);
    }

    return result;
}

/** Create a snapshot */
ecs_snapshot_t* ecs_snapshot_take(
    ecs_world_t *world)
{
    ecs_snapshot_t *result = snapshot_create(
        world,
        world->store.entity_index,
        NULL,
        NULL);

    result->last_id = world->stats.last_id;

    return result;
}

/** Create a filtered snapshot */
ecs_snapshot_t* ecs_snapshot_take_w_iter(
    ecs_iter_t *iter,
    ecs_iter_next_action_t next)
{
    ecs_world_t *world = iter->world;
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_snapshot_t *result = snapshot_create(
        world,
        world->store.entity_index,
        iter,
        next);

    result->last_id = world->stats.last_id;

    return result;
}

/** Restore a snapshot */
void ecs_snapshot_restore(
    ecs_world_t *world,
    ecs_snapshot_t *snapshot)
{
    bool is_filtered = true;

    if (snapshot->entity_index) {
        ecs_sparse_restore(world->store.entity_index, snapshot->entity_index);
        ecs_sparse_free(snapshot->entity_index);
        is_filtered = false;
    }

    if (!is_filtered) {
        world->stats.last_id = snapshot->last_id;
    }

    ecs_table_leaf_t *leafs = ecs_vector_first(snapshot->tables, ecs_table_leaf_t);
    int32_t l = 0, count = ecs_vector_count(snapshot->tables);
    int32_t t, table_count = ecs_sparse_count(world->store.tables);

    for (t = 0; t < table_count; t ++) {
        ecs_table_t *table = ecs_sparse_get(world->store.tables, ecs_table_t, t);

        if (table->flags & EcsTableHasBuiltins) {
            continue;
        }

        ecs_table_leaf_t *leaf = NULL;
        if (l < count) {
            leaf = &leafs[l];
        }

        if (leaf && leaf->table == table) {
            /* If the snapshot is filtered, update the entity index for the
             * entities in the snapshot. If the snapshot was not filtered
             * the entity index would have been replaced entirely, and this
             * is not necessary. */
            if (is_filtered) {
                ecs_vector_each(leaf->data->entities, ecs_entity_t, e_ptr, {
                    ecs_record_t *r = ecs_eis_get(world, *e_ptr);
                    if (r && r->table) {
                        ecs_data_t *data = ecs_table_get_data(r->table);
                        
                        /* Data must be not NULL, otherwise entity index could
                         * not point to it */
                        ecs_assert(data != NULL, ECS_INTERNAL_ERROR, NULL);

                        bool is_monitored;
                        int32_t row = ecs_record_to_row(r->row, &is_monitored);
                        
                        /* Always delete entity, so that even if the entity is
                        * in the current table, there won't be duplicates */
                        ecs_table_delete(world, r->table, data, row, true);
                    } else {
                        ecs_eis_set_generation(world, *e_ptr);
                    }
                });

                int32_t old_count = ecs_table_count(table);
                int32_t new_count = ecs_table_data_count(leaf->data);

                ecs_data_t *data = ecs_table_get_data(table);
                data = ecs_table_merge(world, table, table, data, leaf->data);

                /* Run OnSet systems for merged entities */
                ecs_entities_t components = ecs_type_to_entities(table->type);
                ecs_run_set_systems(world, &components, table, data,
                    old_count, new_count, true);

                ecs_os_free(leaf->data->columns);
            } else {
                ecs_table_replace_data(world, table, leaf->data);
            }
            
            ecs_os_free(leaf->data);
            l ++;
        } else {
            /* If the snapshot is not filtered, the snapshot should restore the
             * world to the exact state it was in. When a snapshot is filtered,
             * it should only update the entities that were in the snapshot.
             * If a table is found that was not in the snapshot, and the
             * snapshot was not filtered, clear the table. */
            if (!is_filtered) {
                /* Use clear_silent so no triggers are fired */
                ecs_table_clear_silent(world, table);
            }
        }

        table->alloc_count ++;
    }

    /* If snapshot was not filtered, run OnSet systems now. This cannot be done
     * while restoring the snapshot, because the world is in an inconsistent
     * state while restoring. When a snapshot is filtered, the world is not left
     * in an inconsistent state, which makes running OnSet systems while
     * restoring safe */
    if (!is_filtered) {
        for (t = 0; t < table_count; t ++) {
            ecs_table_t *table = ecs_sparse_get(world->store.tables, ecs_table_t, t);
            if (table->flags & EcsTableHasBuiltins) {
                continue;
            }

            ecs_entities_t components = ecs_type_to_entities(table->type);
            ecs_data_t *table_data = ecs_table_get_data(table);
            int32_t entity_count = ecs_table_data_count(table_data);

            ecs_run_set_systems(world, &components, table, 
                table_data, 0, entity_count, true);            
        }
    }

    ecs_vector_free(snapshot->tables);   

    ecs_os_free(snapshot);
}

ecs_iter_t ecs_snapshot_iter(
    ecs_snapshot_t *snapshot,
    const ecs_filter_t *filter)
{
    ecs_snapshot_iter_t iter = {
        .filter = filter ? *filter : (ecs_filter_t){0},
        .tables = snapshot->tables,
        .index = 0
    };

    return (ecs_iter_t){
        .world = snapshot->world,
        .table_count = ecs_vector_count(snapshot->tables),
        .iter.snapshot = iter
    };
}

bool ecs_snapshot_next(
    ecs_iter_t *it)
{
    ecs_snapshot_iter_t *iter = &it->iter.snapshot;
    ecs_table_leaf_t *tables = ecs_vector_first(iter->tables, ecs_table_leaf_t);
    int32_t count = ecs_vector_count(iter->tables);
    int32_t i;

    for (i = iter->index; i < count; i ++) {
        ecs_table_t *table = tables[i].table;
        ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);

        ecs_data_t *data = tables[i].data;

        /* Table must have data or it wouldn't have been added */
        ecs_assert(data != NULL, ECS_INTERNAL_ERROR, NULL);

        if (!ecs_table_match_filter(it->world, table, &iter->filter)) {
            continue;
        }

        iter->table.table = table;
        it->table = &iter->table;
        it->table_columns = data->columns;
        it->count = ecs_table_data_count(data);
        it->entities = ecs_vector_first(data->entities, ecs_entity_t);
        iter->index = i + 1;

        return true;
    }

    return false;    
}

/** Cleanup snapshot */
void ecs_snapshot_free(
    ecs_snapshot_t *snapshot)
{
    ecs_sparse_free(snapshot->entity_index);

    ecs_table_leaf_t *tables = ecs_vector_first(snapshot->tables, ecs_table_leaf_t);
    int32_t i, count = ecs_vector_count(snapshot->tables);
    for (i = 0; i < count; i ++) {
        ecs_table_leaf_t *leaf = &tables[i];
        ecs_table_clear_data(snapshot->world, leaf->table, leaf->data);
        ecs_os_free(leaf->data);
    }    

    ecs_vector_free(snapshot->tables);
    ecs_os_free(snapshot);
}

#endif

#ifdef FLECS_DBG


ecs_table_t *ecs_dbg_find_table(
    ecs_world_t *world,
    ecs_type_t type)
{
    ecs_table_t *table = ecs_table_from_type(world, type);
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);
    return table;
}

void ecs_dbg_table(
    ecs_world_t *world, 
    ecs_table_t *table, 
    ecs_dbg_table_t *dbg_out)
{
    ecs_assert(dbg_out != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(table != NULL, ECS_INVALID_PARAMETER, NULL);

    *dbg_out = (ecs_dbg_table_t){.table = table};

    dbg_out->type = table->type;
    dbg_out->systems_matched = table->queries;

    /* Determine components from parent/base entities */
    ecs_entity_t *entities = ecs_vector_first(table->type, ecs_entity_t);
    int32_t i, count = ecs_vector_count(table->type);

    for (i = 0; i < count; i ++) {
        ecs_entity_t e = entities[i];

        if (ECS_HAS_RELATION(e, EcsChildOf)) {
            ecs_dbg_entity_t parent_dbg;
            ecs_dbg_entity(world, ECS_PAIR_OBJECT(e), &parent_dbg);

            ecs_dbg_table_t parent_table_dbg;
            ecs_dbg_table(world, parent_dbg.table, &parent_table_dbg);

            /* Owned and shared components are available from container */
            dbg_out->container = ecs_type_merge(
                world, dbg_out->container, parent_dbg.type, NULL);
            dbg_out->container = ecs_type_merge(
                world, dbg_out->container, parent_table_dbg.shared, NULL);

            /* Add entity to list of parent entities */
            dbg_out->parent_entities = ecs_type_add(
                world, dbg_out->parent_entities, ECS_PAIR_OBJECT(e));
        }

        if (ECS_HAS_RELATION(e, EcsIsA)) {
            ecs_dbg_entity_t base_dbg;
            ecs_dbg_entity(world, ECS_PAIR_OBJECT(e), &base_dbg);

            ecs_dbg_table_t base_table_dbg;
            ecs_dbg_table(world, base_dbg.table, &base_table_dbg);            

            /* Owned and shared components are available from base */
            dbg_out->shared = ecs_type_merge(
                world, dbg_out->shared, base_dbg.type, NULL);
            dbg_out->shared = ecs_type_merge(
                world, dbg_out->shared, base_table_dbg.shared, NULL);

            /* Never inherit EcsName or EcsPrefab */
            dbg_out->shared = ecs_type_merge(
                world, dbg_out->shared, NULL, ecs_type(EcsName));
            dbg_out->shared = ecs_type_merge(
                world, dbg_out->shared, NULL, ecs_type_from_id(world, EcsPrefab));

            /* Shared components are always masked by owned components */
            dbg_out->shared = ecs_type_merge(
                world, dbg_out->shared, NULL, table->type);

            /* Add entity to list of base entities */
            dbg_out->base_entities = ecs_type_add(
                world, dbg_out->base_entities, ECS_PAIR_OBJECT(e));

            /* Add base entities of entity to list of base entities */
            dbg_out->base_entities = ecs_type_add(
                world, base_table_dbg.base_entities, ECS_PAIR_OBJECT(e));
        }
    }

    ecs_data_t *data = ecs_table_get_data(table);
    if (data) {
        dbg_out->entities = ecs_vector_first(data->entities, ecs_entity_t);
        dbg_out->entities_count = ecs_vector_count(data->entities);
    }
}

ecs_table_t* ecs_dbg_get_table(
    const ecs_world_t *world,
    int32_t index)
{
    if (ecs_sparse_count(world->store.tables) <= index) {
        return NULL;
    }

    return ecs_sparse_get(
        world->store.tables, ecs_table_t, index);
}

bool ecs_dbg_filter_table(
    const ecs_world_t *world,
    const ecs_table_t *table,
    const ecs_filter_t *filter)
{
    return ecs_table_match_filter(world, table, filter);
}

void ecs_dbg_entity(
    const ecs_world_t *world, 
    ecs_entity_t entity, 
    ecs_dbg_entity_t *dbg_out)
{
    *dbg_out = (ecs_dbg_entity_t){.entity = entity};
    
    ecs_entity_info_t info = { 0 };
    if (ecs_get_info(world, entity, &info)) {
        dbg_out->table = info.table;
        dbg_out->row = info.row;
        dbg_out->is_watched = info.is_watched;
        dbg_out->type = info.table ? info.table->type : NULL;
    }
}

#endif

#ifdef FLECS_READER_WRITER


static
bool iter_table(
    ecs_table_reader_t *reader,
    ecs_iter_t *it,
    ecs_iter_next_action_t next,
    bool skip_builtin)    
{
    bool table_found = false;

    while (next(it)) {
        ecs_table_t *table = it->table->table;

        reader->table = table;
        ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);

        ecs_data_t *data = ecs_table_get_data(table);
        reader->data = data;
        reader->table_index ++;

        if (skip_builtin && reader->table->flags & EcsTableHasBuiltins) {
            continue;
        }

        if (!data || !it->count) {
            continue;
        }

        table_found = true;
        break;
    }

    return table_found;
}

static
void next_table(
    ecs_reader_t *stream,
    ecs_table_reader_t *reader)
{    
    int32_t count;

    /* First iterate all component tables, as component data must always be
     * stored in a blob before anything else */
    bool table_found = iter_table(
        reader, &stream->component_iter, stream->component_next, false);

    /* If all components have been added, add the regular data tables. Make sure
     * to not add component tables again, in case the provided iterator also
     * matches component tables. */
    if (!table_found) {
        table_found = iter_table(
            reader, &stream->data_iter, stream->data_next, true);
        count = stream->data_iter.count;
    } else {
        count = stream->component_iter.count;
    }

    if (!table_found) {
        stream->state = EcsFooterSegment;
    } else {
        reader->type = reader->table->type;
        reader->total_columns = reader->table->column_count + 1;
        reader->column_index = 0;
        reader->row_count = count;
    }
}

static
void ecs_table_reader_next(
    ecs_reader_t *stream)
{
    ecs_table_reader_t *reader = &stream->table;

    switch(reader->state) {
    case EcsTableHeader:
        reader->state = EcsTableTypeSize;
        break;
    case EcsTableTypeSize:
        reader->state = EcsTableType;
        reader->type_written = 0;
        break;

    case EcsTableType:
        reader->state = EcsTableSize;
        break;

    case EcsTableSize: {
        reader->state = EcsTableColumnHeader;
        break;
    }

    case EcsTableColumnHeader:
        reader->state = EcsTableColumnSize;
        if (!reader->column_index) {
            reader->column_vector = reader->data->entities;
            reader->column_size = ECS_SIZEOF(ecs_entity_t);
        } else {
            ecs_column_t *column = 
                &reader->data->columns[reader->column_index - 1];
            reader->column_vector = column->data;
            reader->column_size = column->size;
            reader->column_alignment = column->alignment;
        }
        break;

    case EcsTableColumnSize:
        reader->state = EcsTableColumnData;
        reader->column_data = ecs_vector_first_t(reader->column_vector, 
            reader->column_size, reader->column_alignment);
        reader->column_written = 0;
        break;

    case EcsTableColumnNameHeader: {
        reader->state = EcsTableColumnNameLength;
        ecs_column_t *column = 
                &reader->data->columns[reader->column_index - 1];
        reader->column_vector = column->data;                
        reader->column_data = ecs_vector_first(reader->column_vector, EcsName);
        reader->row_index = 0;
        break;
    }

    case EcsTableColumnNameLength:
        reader->state = EcsTableColumnName;
        reader->row_index ++;
        break;

    case EcsTableColumnName:
        if (reader->row_index < reader->row_count) {
            reader->state = EcsTableColumnNameLength;
            break;
        }
        // fall through

    case EcsTableColumnData:
        reader->column_index ++;
        if (reader->column_index == reader->total_columns) {
            reader->state = EcsTableHeader;
            next_table(stream, reader);
        } else {
            ecs_entity_t *type_buffer = ecs_vector_first(reader->type, ecs_entity_t);
            if (reader->column_index >= 1) {
                ecs_entity_t e = type_buffer[reader->column_index - 1];
                
                if (e != ecs_id(EcsName)) {
                    reader->state = EcsTableColumnHeader;
                } else {
                    reader->state = EcsTableColumnNameHeader;
                }
            } else {
                reader->state = EcsTableColumnHeader;
            }            
        }
        break;

    default:
        ecs_abort(ECS_INTERNAL_ERROR, NULL);
    }

    return;
}

static
ecs_size_t ecs_table_reader(
    char *buffer,
    ecs_size_t size,
    ecs_reader_t *stream)
{
    if (!size) {
        return 0;
    }

    if (size < ECS_SIZEOF(int32_t)) {
        return -1;
    }

    ecs_table_reader_t *reader = &stream->table;
    ecs_size_t read = 0;

    if (!reader->state) {
        next_table(stream, reader);
        reader->state = EcsTableHeader;
    }

    switch(reader->state) {
    case EcsTableHeader:
        ecs_os_memcpy(buffer, &(ecs_blob_header_kind_t){EcsTableHeader}, ECS_SIZEOF(EcsTableHeader));
        read = ECS_SIZEOF(ecs_blob_header_kind_t);
        ecs_table_reader_next(stream);
        break;

    case EcsTableTypeSize:
        ecs_os_memcpy(buffer, &(int32_t){ecs_vector_count(reader->type)}, ECS_SIZEOF(int32_t));
        read = ECS_SIZEOF(int32_t);
        ecs_table_reader_next(stream);
        break;  

    case EcsTableType: {
        ecs_entity_t *type_array = ecs_vector_first(reader->type, ecs_entity_t);
        ecs_os_memcpy(buffer, ECS_OFFSET(type_array, reader->type_written), ECS_SIZEOF(int32_t));
        reader->type_written += ECS_SIZEOF(int32_t);
        read = ECS_SIZEOF(int32_t);

        if (reader->type_written == ecs_vector_count(reader->type) * ECS_SIZEOF(ecs_entity_t)) {
            ecs_table_reader_next(stream);
        }
        break;                
    }

    case EcsTableSize:
        ecs_os_memcpy(buffer, &(int32_t){ecs_table_count(reader->table)}, ECS_SIZEOF(int32_t));
        read = ECS_SIZEOF(int32_t);
        ecs_table_reader_next(stream);
        break;

    case EcsTableColumnHeader:
        ecs_os_memcpy(buffer, &(ecs_blob_header_kind_t){EcsTableColumnHeader}, ECS_SIZEOF(ecs_blob_header_kind_t));
        read = ECS_SIZEOF(ecs_blob_header_kind_t);
        ecs_table_reader_next(stream);
        break; 

    case EcsTableColumnSize: {
        int32_t column_size = reader->column_size;
        ecs_os_memcpy(buffer, &column_size, ECS_SIZEOF(int32_t));
        read = ECS_SIZEOF(ecs_blob_header_kind_t);
        ecs_table_reader_next(stream);

        if (!reader->column_size) {
            ecs_table_reader_next(stream);
        }
        break; 
    }

    case EcsTableColumnData: {
        ecs_size_t column_bytes = reader->column_size * reader->row_count;
        read = column_bytes - reader->column_written;
        if (read > size) {
            read = size;
        }

        ecs_os_memcpy(buffer, ECS_OFFSET(reader->column_data, reader->column_written), read);
        reader->column_written += read;
        ecs_assert(reader->column_written <= column_bytes, ECS_INTERNAL_ERROR, NULL);

        ecs_size_t align = (((read - 1) / ECS_SIZEOF(int32_t)) + 1) * ECS_SIZEOF(int32_t);
        if (align != read) {
            /* Initialize padding bytes to 0 to keep valgrind happy */
            ecs_os_memset(ECS_OFFSET(buffer, read), 0, align - read);

            /* Set read to align so that data is always aligned to 4 bytes */
            read = align;

            /* Buffer sizes are expected to be aligned to 4 bytes and the rest
             * of the serialized data is aligned to 4 bytes. Should never happen
             * that adding padding bytes exceeds the size. */
            ecs_assert(read <= size, ECS_INTERNAL_ERROR, NULL);
        }

        if (reader->column_written == column_bytes) {
            ecs_table_reader_next(stream);
        }
        break;
    }

    case EcsTableColumnNameHeader:
        ecs_os_memcpy(buffer, &(ecs_blob_header_kind_t){EcsTableColumnNameHeader}, ECS_SIZEOF(ecs_blob_header_kind_t));
        read = ECS_SIZEOF(ecs_blob_header_kind_t);
        ecs_table_reader_next(stream);
        break;

    case EcsTableColumnNameLength: {
        reader->name = ((EcsName*)reader->column_data)[reader->row_index].value;
        reader->name_len = ecs_os_strlen(reader->name) + 1;
        reader->name_written = 0;
        int32_t name_len = reader->name_len;
        ecs_os_memcpy(buffer, &name_len, ECS_SIZEOF(int32_t));
        // *(int32_t*)buffer = reader->name_len;
        read = ECS_SIZEOF(int32_t);
        ecs_table_reader_next(stream);    
        break;
    }

    case EcsTableColumnName:   
        read = reader->name_len - reader->name_written;
        if (read >= ECS_SIZEOF(int32_t)) {

            int32_t i;
            for (i = 0; i < 4; i ++) {
                *(char*)ECS_OFFSET(buffer, i) = 
                    *(char*)ECS_OFFSET(reader->name, reader->name_written + i);
            }

            reader->name_written += ECS_SIZEOF(int32_t);
        } else {
            ecs_os_memcpy(buffer, ECS_OFFSET(reader->name, reader->name_written), read);
            ecs_os_memset(ECS_OFFSET(buffer, read), 0, ECS_SIZEOF(int32_t) - read);
            reader->name_written += read;
        }

        /* Always align buffer to multiples of 4 bytes */
        read = ECS_SIZEOF(int32_t);

        if (reader->name_written == reader->name_len) {
            ecs_table_reader_next(stream);
        }

        break;

    default:
        ecs_abort(ECS_INTERNAL_ERROR, NULL);
    }

    ecs_assert(read % 4 == 0, ECS_INTERNAL_ERROR, NULL);

    return read;
}

int32_t ecs_reader_read(
    char *buffer,
    int32_t size,
    ecs_reader_t *reader)
{
    int32_t read, total_read = 0, remaining = size;

    if (!size) {
        return 0;
    }

    ecs_assert(size >= ECS_SIZEOF(int32_t), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(size % 4 == 0, ECS_INVALID_PARAMETER, NULL);

    if (reader->state == EcsTableSegment) {
        while ((read = ecs_table_reader(ECS_OFFSET(buffer, total_read), remaining, reader))) {
            remaining -= read;
            total_read += read;

            if (reader->state != EcsTableSegment) {
                break;
            }

            ecs_assert(remaining % 4 == 0, ECS_INTERNAL_ERROR, NULL);        
        }
    }  
    
    return total_read;
}

ecs_reader_t ecs_reader_init(
    ecs_world_t *world)
{
    ecs_reader_t result = {
        .world = world,
        .state = EcsTableSegment,
        .component_iter = ecs_filter_iter(world, &(ecs_filter_t){
            .include = ecs_type(EcsComponent)
        }),
        .component_next = ecs_filter_next,
        .data_iter = ecs_filter_iter(world, NULL),
        .data_next = ecs_filter_next
    };

    return result;
}

ecs_reader_t ecs_reader_init_w_iter(
    ecs_iter_t *it,
    ecs_iter_next_action_t next)
{
    ecs_world_t *world = it->world;

    ecs_reader_t result = {
        .world = world,
        .state = EcsTableSegment,
        .component_iter = ecs_filter_iter(world, &(ecs_filter_t){
            .include = ecs_type(EcsComponent)
        }),
        .component_next = ecs_filter_next,
        .data_iter = *it,
        .data_next = next
    };

    return result;
}

#endif

#ifdef FLECS_BULK


static
void bulk_delete(
    ecs_world_t *world,
    const ecs_filter_t *filter,
    bool is_delete)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_stage_t *stage = ecs_stage_from_world(&world);
    ecs_assert(stage == &world->stage, ECS_UNSUPPORTED, NULL);
    (void)stage;

    int32_t i, count = ecs_sparse_count(world->store.tables);

    for (i = 0; i < count; i ++) {
        ecs_table_t *table = ecs_sparse_get(world->store.tables, ecs_table_t, i);

        if (table->flags & EcsTableHasBuiltins) {
            continue;
        }

        if (!ecs_table_match_filter(world, table, filter)) {
            continue;
        }

        /* Remove entities from index */
        ecs_data_t *data = ecs_table_get_data(table);
        if (!data) {
            /* If table has no data, there's nothing to delete */
            continue;
        }

        /* Both filters passed, clear table */
        if (is_delete) {
            ecs_table_delete_entities(world, table);
        } else {
            ecs_table_clear_silent(world, table);
        }
    }
}

static
void merge_table(
    ecs_world_t *world,
    ecs_table_t *dst_table,
    ecs_table_t *src_table,
    ecs_entities_t *to_add,
    ecs_entities_t *to_remove)
{    
    if (!dst_table->type) {
        /* If this removes all components, clear table */
        ecs_table_clear(world, src_table);
    } else {
        /* Merge table into dst_table */
        if (dst_table != src_table) {
            ecs_data_t *src_data = ecs_table_get_data(src_table);
            int32_t dst_count = ecs_table_count(dst_table);
            int32_t src_count = ecs_table_count(src_table);

            if (to_remove && to_remove->count && src_data) {
                ecs_run_remove_actions(world, src_table, 
                    src_data, 0, src_count, to_remove);
            }

            ecs_data_t *dst_data = ecs_table_get_data(dst_table);
            dst_data = ecs_table_merge(
                world, dst_table, src_table, dst_data, src_data);

            if (to_add && to_add->count && dst_data) {
                ecs_run_add_actions(world, dst_table, dst_data, 
                    dst_count, src_count, to_add, false, true);
            }
        }
    }
}

/* -- Public API -- */

void ecs_bulk_delete(
    ecs_world_t *world,
    const ecs_filter_t *filter)
{
    bulk_delete(world, filter, true);
}

void ecs_bulk_add_remove_type(
    ecs_world_t *world,
    ecs_type_t to_add,
    ecs_type_t to_remove,
    const ecs_filter_t *filter)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_stage_t *stage = ecs_stage_from_world(&world);
    ecs_assert(stage == &world->stage, ECS_UNSUPPORTED, NULL);
    (void)stage;

    ecs_entities_t to_add_array = ecs_type_to_entities(to_add);
    ecs_entities_t to_remove_array = ecs_type_to_entities(to_remove);

    ecs_entities_t added = {
        .array = ecs_os_alloca(ECS_SIZEOF(ecs_entity_t) * to_add_array.count),
        .count = 0
    }; 

    ecs_entities_t removed = {
        .array = ecs_os_alloca(ECS_SIZEOF(ecs_entity_t) * to_remove_array.count),
        .count = 0
    };

    int32_t i, count = ecs_sparse_count(world->store.tables);
    for (i = 0; i < count; i ++) {
        ecs_table_t *table = ecs_sparse_get(world->store.tables, ecs_table_t, i);

        if (table->flags & EcsTableHasBuiltins) {
            continue;
        }

        if (!ecs_table_match_filter(world, table, filter)) {
            continue;
        }

        ecs_table_t *dst_table = ecs_table_traverse_remove(
            world, table, &to_remove_array, &removed);
        
        dst_table = ecs_table_traverse_add(
            world, dst_table, &to_add_array, &added);

        ecs_assert(removed.count <= to_remove_array.count, ECS_INTERNAL_ERROR, NULL);
        ecs_assert(added.count <= to_add_array.count, ECS_INTERNAL_ERROR, NULL);

        if (table == dst_table || (!added.count && !removed.count)) {
            continue;
        }

        ecs_assert(dst_table != NULL, ECS_INTERNAL_ERROR, NULL);   

        merge_table(world, dst_table, table, &added, &removed);
        added.count = 0;
        removed.count = 0;
    }    
}

void ecs_bulk_add_type(
    ecs_world_t *world,
    ecs_type_t to_add,
    const ecs_filter_t *filter)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(to_add != NULL, ECS_INVALID_PARAMETER, NULL);
    
    ecs_stage_t *stage = ecs_stage_from_world(&world);
    ecs_assert(stage == &world->stage, ECS_UNSUPPORTED, NULL);
    (void)stage;

    ecs_entities_t to_add_array = ecs_type_to_entities(to_add);
    ecs_entities_t added = {
        .array = ecs_os_alloca(ECS_SIZEOF(ecs_entity_t) * to_add_array.count),
        .count = 0
    };

    int32_t i, count = ecs_sparse_count(world->store.tables);
    for (i = 0; i < count; i ++) {
        ecs_table_t *table = ecs_sparse_get(world->store.tables, ecs_table_t, i);

        if (table->flags & EcsTableHasBuiltins) {
            continue;
        }

        if (!ecs_table_match_filter(world, table, filter)) {
            continue;
        }
        
        ecs_table_t *dst_table = ecs_table_traverse_add(
            world, table, &to_add_array, &added);
        
        ecs_assert(added.count <= to_add_array.count, ECS_INTERNAL_ERROR, NULL);

        if (!added.count) {
            continue;
        }

        ecs_assert(dst_table != NULL, ECS_INTERNAL_ERROR, NULL);
        merge_table(world, dst_table, table, &added, NULL);
        added.count = 0;
    }    
}

void ecs_bulk_add_entity(
    ecs_world_t *world,
    ecs_entity_t to_add,
    const ecs_filter_t *filter)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(to_add != 0, ECS_INVALID_PARAMETER, NULL);

    ecs_stage_t *stage = ecs_stage_from_world(&world);
    ecs_assert(stage == &world->stage, ECS_UNSUPPORTED, NULL);
    (void)stage;

    ecs_entities_t to_add_array = { .array = &to_add, .count = 1 };

    ecs_entity_t added_entity;
    ecs_entities_t added = {
        .array = &added_entity,
        .count = 0
    };

    int32_t i, count = ecs_sparse_count(world->store.tables);
    for (i = 0; i < count; i ++) {
        ecs_table_t *table = ecs_sparse_get(world->store.tables, ecs_table_t, i);

        if (table->flags & EcsTableHasBuiltins) {
            continue;
        }

        if (!ecs_table_match_filter(world, table, filter)) {
            continue;
        }
        
        ecs_table_t *dst_table = ecs_table_traverse_add(
            world, table, &to_add_array, &added);

        ecs_assert(added.count <= to_add_array.count, ECS_INTERNAL_ERROR, NULL);
        
        if (!added.count) {
            continue;
        }         

        ecs_assert(dst_table != NULL, ECS_INTERNAL_ERROR, NULL);   
        merge_table(world, dst_table, table, &added, NULL);
        added.count = 0;
    }    
}

void ecs_bulk_remove_type(
    ecs_world_t *world,
    ecs_type_t to_remove,
    const ecs_filter_t *filter)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(to_remove != NULL, ECS_INVALID_PARAMETER, NULL);

    ecs_stage_t *stage = ecs_stage_from_world(&world);
    ecs_assert(stage == &world->stage, ECS_UNSUPPORTED, NULL);
    (void)stage;

    ecs_entities_t to_remove_array = ecs_type_to_entities(to_remove);
    ecs_entities_t removed = {
        .array = ecs_os_alloca(ECS_SIZEOF(ecs_entity_t) * to_remove_array.count),
        .count = 0
    };

    int32_t i, count = ecs_sparse_count(world->store.tables);
    for (i = 0; i < count; i ++) {
        ecs_table_t *table = ecs_sparse_get(world->store.tables, ecs_table_t, i);

        if (table->flags & EcsTableHasBuiltins) {
            continue;
        }

        if (!ecs_table_match_filter(world, table, filter)) {
            continue;
        }
        
        ecs_table_t *dst_table = ecs_table_traverse_remove(
            world, table, &to_remove_array, &removed);

        ecs_assert(removed.count <= to_remove_array.count, ECS_INTERNAL_ERROR, NULL);

        if (!removed.count) {
            continue;
        }

        ecs_assert(dst_table != NULL, ECS_INTERNAL_ERROR, NULL);
        merge_table(world, dst_table, table, NULL, &removed);
        removed.count = 0;        
    }    
}

void ecs_bulk_remove_entity(
    ecs_world_t *world,
    ecs_entity_t to_remove,
    const ecs_filter_t *filter)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(to_remove != 0, ECS_INVALID_PARAMETER, NULL);

    ecs_stage_t *stage = ecs_stage_from_world(&world);
    ecs_assert(stage == &world->stage, ECS_UNSUPPORTED, NULL);
    (void)stage;

    ecs_entities_t to_remove_array = { .array = &to_remove, .count = 1 };

    ecs_entity_t removed_entity;
    ecs_entities_t removed = {
        .array = &removed_entity,
        .count = 0
    };

    int32_t i, count = ecs_sparse_count(world->store.tables);
    for (i = 0; i < count; i ++) {
        ecs_table_t *table = ecs_sparse_get(world->store.tables, ecs_table_t, i);

        if (table->flags & EcsTableHasBuiltins) {
            continue;
        }

        if (!ecs_table_match_filter(world, table, filter)) {
            continue;
        }            

        ecs_table_t *dst_table = ecs_table_traverse_remove(
            world, table, &to_remove_array, &removed);

        ecs_assert(removed.count <= to_remove_array.count, ECS_INTERNAL_ERROR, NULL);

        if (!removed.count) {
            continue;
        }

        ecs_assert(dst_table != NULL, ECS_INTERNAL_ERROR, NULL);   
        merge_table(world, dst_table, table, NULL, &removed);
        removed.count = 0;        
    }    
}

#endif

#ifdef FLECS_PARSER


/* TODO: after new query parser is working & code is ported to new types for
 *       storing terms, this code needs a big cleanup */

#define ECS_ANNOTATION_LENGTH_MAX (16)

#define TOK_COLON ':'
#define TOK_AND ','
#define TOK_OR "||"
#define TOK_NOT '!'
#define TOK_OPTIONAL '?'
#define TOK_BITWISE_OR '|'
#define TOK_TRAIT '>'
#define TOK_FOR "FOR"
#define TOK_NAME_SEP '.'
#define TOK_BRACKET_OPEN '['
#define TOK_BRACKET_CLOSE ']'
#define TOK_WILDCARD '*'
#define TOK_SINGLETON '$'
#define TOK_PAREN_OPEN '('
#define TOK_PAREN_CLOSE ')'
#define TOK_AS_ENTITY '\\'

#define TOK_SELF "self"
#define TOK_SUPERSET "superset"
#define TOK_SUBSET "subset"
#define TOK_ALL "all"

#define TOK_ANY "ANY"
#define TOK_OWNED "OWNED"
#define TOK_SHARED "SHARED"
#define TOK_SYSTEM "SYSTEM"
#define TOK_PARENT "PARENT"
#define TOK_CASCADE "CASCADE"

#define TOK_ROLE_CHILDOF "CHILDOF"
#define TOK_ROLE_INSTANCEOF "INSTANCEOF"
#define TOK_ROLE_TRAIT "TRAIT"
#define TOK_ROLE_PAIR "PAIR"
#define TOK_ROLE_AND "AND"
#define TOK_ROLE_OR "OR"
#define TOK_ROLE_XOR "XOR"
#define TOK_ROLE_NOT "NOT"
#define TOK_ROLE_SWITCH "SWITCH"
#define TOK_ROLE_CASE "CASE"
#define TOK_ROLE_DISABLED "DISABLED"

#define TOK_IN "in"
#define TOK_OUT "out"
#define TOK_INOUT "inout"

#define ECS_MAX_TOKEN_SIZE (256)

typedef char ecs_token_t[ECS_MAX_TOKEN_SIZE];

/** Skip spaces when parsing signature */
static
const char *skip_space(
    const char *ptr)
{
    while (isspace(*ptr)) {
        ptr ++;
    }
    return ptr;
}

/* -- Private functions -- */

static
bool valid_token_start_char(
    char ch)
{
    if (ch && (isalpha(ch) || (ch == '.') || (ch == '_') || (ch == '*') ||
        (ch == '0') || (ch == TOK_AS_ENTITY) || isdigit(ch))) 
    {
        return true;
    }

    return false;
}

static
bool valid_token_char(
    char ch)
{
    if (ch && (isalpha(ch) || isdigit(ch) || ch == '_' || ch == '.')) {
        return true;
    }

    return false;
}

static
bool valid_operator_char(
    char ch)
{
    if (ch == TOK_OPTIONAL || ch == TOK_NOT) {
        return true;
    }

    return false;
}

static
const char* parse_digit(
    const char *name,
    const char *sig,
    int64_t column,
    const char *ptr,
    char *token_out)
{
    ptr = skip_space(ptr);
    char *tptr = token_out, ch = ptr[0];

    if (!isdigit(ch)) {
        ecs_parser_error(name, sig, column, 
            "invalid start of number '%s'", ptr);
        return NULL;
    }

    tptr[0] = ch;
    tptr ++;
    ptr ++;

    for (; (ch = *ptr); ptr ++) {
        if (!isdigit(ch)) {
            break;
        }

        tptr[0] = ch;
        tptr ++;
    }

    tptr[0] = '\0';

    return skip_space(ptr);
}


static
const char* parse_token(
    const char *name,
    const char *sig,
    int64_t column,
    const char *ptr,
    char *token_out)
{
    ptr = skip_space(ptr);
    char *tptr = token_out, ch = ptr[0];

    if (!valid_token_start_char(ch)) {
        ecs_parser_error(name, sig, column, 
            "invalid start of identifier '%s'", ptr);
        return NULL;
    }

    tptr[0] = ch;
    tptr ++;
    ptr ++;

    for (; (ch = *ptr); ptr ++) {
        if (!valid_token_char(ch)) {
            break;
        }

        tptr[0] = ch;
        tptr ++;
    }

    tptr[0] = '\0';

    return skip_space(ptr);
}

static
int parse_identifier(
    const char *token,
    ecs_term_id_t *out)
{
    char ch = token[0];

    const char *tptr = token;
    if (ch == TOK_AS_ENTITY) {
        tptr ++;
    }

    out->name = ecs_os_strdup(tptr);

    if (ch == TOK_AS_ENTITY) {
        out->var_kind = EcsVarIsEntity;
    } else if (ecs_identifier_is_var(tptr)) {
        out->var_kind = EcsVarIsVariable;
    }

    return 0;
}

static
ecs_entity_t parse_role(
    const char *name,
    const char *sig,
    int64_t column,
    const char *token)
{
    if        (!ecs_os_strcmp(token, TOK_ROLE_CHILDOF)) {
        return ECS_CHILDOF;
    } else if (!ecs_os_strcmp(token, TOK_ROLE_INSTANCEOF)) {
        return ECS_INSTANCEOF;
    } else if (!ecs_os_strcmp(token, TOK_ROLE_TRAIT) || 
               !ecs_os_strcmp(token, TOK_ROLE_PAIR)) 
    {
        return ECS_PAIR;            
    } else if (!ecs_os_strcmp(token, TOK_ROLE_AND)) {
        return ECS_AND;
    } else if (!ecs_os_strcmp(token, TOK_ROLE_OR)) {
        return ECS_OR;
    } else if (!ecs_os_strcmp(token, TOK_ROLE_XOR)) {
        return ECS_XOR;
    } else if (!ecs_os_strcmp(token, TOK_ROLE_NOT)) {
        return ECS_NOT;
    } else if (!ecs_os_strcmp(token, TOK_ROLE_SWITCH)) {
        return ECS_SWITCH;
    } else if (!ecs_os_strcmp(token, TOK_ROLE_CASE)) {
        return ECS_CASE;
    } else if (!ecs_os_strcmp(token, TOK_OWNED)) {
        return ECS_OWNED;
    } else if (!ecs_os_strcmp(token, TOK_ROLE_DISABLED)) {
        return ECS_DISABLED;        
    } else {
        ecs_parser_error(name, sig, column, "invalid role '%s'", token);
        return 0;
    }
}

static
ecs_oper_kind_t parse_operator(
    char ch)
{
    if (ch == TOK_OPTIONAL) {
        return EcsOptional;
    } else if (ch == TOK_NOT) {
        return EcsNot;
    } else {
        ecs_abort(ECS_INTERNAL_ERROR, NULL);
    }
}

static
const char* parse_annotation(
    const char *name,
    const char *sig,
    int64_t column,
    const char *ptr, 
    ecs_inout_kind_t *inout_kind_out)
{
    char token[ECS_MAX_TOKEN_SIZE];

    ptr = parse_token(name, sig, column, ptr, token);
    if (!ptr) {
        return NULL;
    }

    if (!strcmp(token, "in")) {
        *inout_kind_out = EcsIn;
    } else
    if (!strcmp(token, "out")) {
        *inout_kind_out = EcsOut;
    } else
    if (!strcmp(token, "inout")) {
        *inout_kind_out = EcsInOut;
    }

    ptr = skip_space(ptr);

    if (ptr[0] != TOK_BRACKET_CLOSE) {
        ecs_parser_error(name, sig, column, "expected ]");
        return NULL;
    }

    return ptr + 1;
}

static
uint8_t parse_set_token(
    const char *token)
{
    if (!ecs_os_strcmp(token, TOK_SELF)) {
        return EcsSelf;
    } else if (!ecs_os_strcmp(token, TOK_SUPERSET)) {
        return EcsSuperSet;
    } else if (!ecs_os_strcmp(token, TOK_SUBSET)) {
        return EcsSubSet;
    } else if (!ecs_os_strcmp(token, TOK_ALL)) {
        return EcsAll;
    } else {
        return 0;
    }
}

static
const char* parse_set_expr(
    const ecs_world_t *world,
    const char *name,
    const char *expr,
    int64_t column,
    const char *ptr,
    char *token,
    ecs_term_id_t *id)
{
    do {
        uint8_t tok = parse_set_token(token);
        if (!tok) {
            ecs_parser_error(name, expr, column, 
                "invalid set token '%s'", token);
            return NULL;
        }

        if (id->set & tok) {
            ecs_parser_error(name, expr, column, 
                "duplicate set token '%s'", token);
            return NULL;            
        }

        if ((tok == EcsSubSet && id->set & EcsSuperSet) ||
            (tok == EcsSuperSet && id->set & EcsSubSet))
        {
            ecs_parser_error(name, expr, column, 
                "cannot mix superset and subset", token);
            return NULL;            
        }    

        id->set |= tok;

        if (ptr[0] == TOK_PAREN_OPEN) {
            ptr ++;

            /* Relationship (overrides IsA default) */
            if (!isdigit(ptr[0]) && valid_token_start_char(ptr[0])) {
                ptr = parse_token(name, expr, (ptr - expr), ptr, token);
                if (!ptr) {
                    return NULL;
                }         

                ecs_entity_t rel = ecs_lookup_fullpath(world, token);
                if (!rel) {
                    ecs_parser_error(name, expr, column, 
                        "unresolved identifier '%s'", token);
                    return NULL;
                }

                id->relation = rel;

                if (ptr[0] == TOK_AND) {
                    ptr = skip_space(ptr + 1);
                } else if (ptr[0] != TOK_PAREN_CLOSE) {
                    ecs_parser_error(name, expr, column, 
                        "expected ',' or ')'");
                    return NULL;
                }
            }

            /* Max depth of search */
            if (isdigit(ptr[0])) {
                ptr = parse_digit(name, expr, (ptr - expr), ptr, token);
                if (!ptr) {
                    return NULL;
                }

                id->max_depth = atoi(token);
                if (id->max_depth < 0) {
                    ecs_parser_error(name, expr, column, 
                        "invalid negative depth");
                    return NULL;  
                }

                if (ptr[0] == ',') {
                    ptr = skip_space(ptr + 1);
                }
            }

            /* If another digit is found, previous depth was min depth */
            if (isdigit(ptr[0])) {
                ptr = parse_digit(name, expr, (ptr - expr), ptr, token);
                if (!ptr) {
                    return NULL;
                }

                id->min_depth = id->max_depth;
                id->max_depth = atoi(token);
                if (id->max_depth < 0) {
                    ecs_parser_error(name, expr, column, 
                        "invalid negative depth");
                    return NULL;  
                }
            }

            if (ptr[0] != TOK_PAREN_CLOSE) {
                ecs_parser_error(name, expr, column, "expected ')'");
                return NULL;                
            } else {
                ptr = skip_space(ptr + 1);
                if (ptr[0] != TOK_PAREN_CLOSE && ptr[0] != TOK_AND) { 
                    ecs_parser_error(name, expr, column, 
                        "expected end of set expr");
                    return NULL;
                }
            }
        }

        /* Next token in set expression */
        if (ptr[0] == TOK_BITWISE_OR) {
            ptr ++;
            if (valid_token_start_char(ptr[0])) {
                ptr = parse_token(name, expr, (ptr - expr), ptr, token);
                if (!ptr) {
                    return NULL;
                }
            }

        /* End of set expression */
        } else if (ptr[0] == TOK_PAREN_CLOSE || ptr[0] == TOK_AND) {
            break;
        }
    } while (true);

    if (id->set & EcsAll && !(id->set & EcsSuperSet) && !(id->set & EcsSubSet)){
        ecs_parser_error(name, expr, column, 
            "invalid 'all' token without superset or subset");
        return NULL;
    }

    if (id->set & EcsSelf && id->min_depth != 0) {
        ecs_parser_error(name, expr, column, 
            "min_depth must be zero for set expression with 'self'");
        return NULL;        
    }

    return ptr;
}

static
const char* parse_arguments(
    const ecs_world_t *world,
    const char *name,
    const char *expr,
    int64_t column,
    const char *ptr,
    char *token,
    ecs_term_t *term)
{
    (void)column;

    int32_t arg = 0;

    do {
        if (valid_token_start_char(ptr[0])) {
            if (arg == 2) {
                ecs_parser_error(name, expr, (ptr - expr), 
                    "too many arguments in term");
                return NULL;
            }

            ptr = parse_token(name, expr, (ptr - expr), ptr, token);
            if (!ptr) {
                return NULL;
            }

            /* If token is a self, superset or subset token, this is a set
             * expression */
            if (!ecs_os_strcmp(token, TOK_ALL) ||
                !ecs_os_strcmp(token, TOK_SELF) || 
                !ecs_os_strcmp(token, TOK_SUPERSET) || 
                !ecs_os_strcmp(token, TOK_SUBSET))
            {
                ptr = parse_set_expr(world, name, expr, (ptr - expr), ptr, 
                    token, &term->args[arg]);

            /* Regular identifier */
            } else if (parse_identifier(token, &term->args[arg])) {
                ecs_parser_error(name, expr, (ptr - expr), 
                    "invalid identifier '%s'", token);
                return NULL;
            }

            if (ptr[0] == TOK_AND) {
                ptr = skip_space(ptr + 1);

            } else if (ptr[0] == TOK_PAREN_CLOSE) {
                ptr = skip_space(ptr + 1);
                break;

            } else {
                ecs_parser_error(name, expr, (ptr - expr), 
                    "expected ',' or ')'");
                return NULL;
            }

        } else {
            ecs_parser_error(name, expr, (ptr - expr), 
                "expected identifier or set expression");
            return NULL;
        }

        arg ++;

    } while (true);

    return ptr;
}

static
const char* parse_term(
    const ecs_world_t *world,
    const char *name,
    const char *expr,
    ecs_term_t *term_out)
{
    const char *ptr = expr;
    char token[ECS_MAX_TOKEN_SIZE] = {0};
    ecs_term_t term = { 0 };

    ptr = skip_space(ptr);

    /* Inout specifiers always come first */
    if (ptr[0] == TOK_BRACKET_OPEN) {
        ptr = parse_annotation(name, expr, (ptr - expr), ptr + 1, &term.inout);
        if (!ptr) {
            return NULL;
        }
        ptr = skip_space(ptr);
    }

    if (valid_operator_char(ptr[0])) {
        term.oper = parse_operator(ptr[0]);
        ptr = skip_space(ptr + 1);
    }

    /* If next token is the start of an identifier, it could be either a type
     * role, source or component identifier */
    if (valid_token_start_char(ptr[0])) {
        ptr = parse_token(name, expr, (ptr - expr), ptr, token);
        if (!ptr) {
            return NULL;
        }
        
        /* Is token a source identifier? */
        if (ptr[0] == TOK_COLON) {
            ptr ++;
            goto parse_source;
        }

        /* Is token a type role? */
        if (ptr[0] == TOK_BITWISE_OR && ptr[1] != TOK_BITWISE_OR) {
            ptr ++;
            goto parse_role;
        }

        /* Is token a trait? (using shorthand notation) */
        if (!ecs_os_strncmp(ptr, TOK_FOR, 3)) {
            term.pred.entity = ECS_PAIR;
            ptr += 3;
            goto parse_trait;
        }

        /* Is token a predicate? */
        if (ptr[0] == TOK_PAREN_OPEN) {
            goto parse_predicate;    
        }

        /* Next token must be a predicate */
        goto parse_predicate;

    /* If next token is the source token, this is an empty source */
    } else if (ptr[0] == TOK_COLON) {
        goto empty_source;

    /* If next token is a singleton, assign identifier to pred and subject */
    } else if (ptr[0] == TOK_SINGLETON) {
        ptr ++;
        if (valid_token_start_char(ptr[0])) {
            ptr = parse_token(name, expr, (ptr - expr), ptr, token);
            if (!ptr) {
                return NULL;
            }

            goto parse_singleton;
        
        /* Deprecated, but still supported: singleton entity */
        } else if (ptr[0] == TOK_COLON) {
            ecs_os_strcpy(token, "$");
            ptr ++;
            goto parse_source;

        } else {
            ecs_parser_error(name, expr, (ptr - expr), 
                "expected identifier after singleton operator");
            return NULL;
        }

    /* Pair with implicit subject */
    } else if (ptr[0] == TOK_PAREN_OPEN) {
        goto parse_pair;

    /* Nothing else expected here */
    } else {
        ecs_parser_error(name, expr, (ptr - expr), 
            "unexpected character '%c'", ptr[0]);
        return NULL;
    }

empty_source:
    term.args[0].set = EcsNothing;
    ptr = skip_space(ptr + 1);
    if (valid_token_start_char(ptr[0])) {
        ptr = parse_token(name, expr, (ptr - expr), ptr, token);
        if (!ptr) {
            return NULL;
        }

        goto parse_predicate;
    } else {
        ecs_parser_error(name, expr, (ptr - expr), 
            "expected identifier after source operator");
        return NULL;
    }

parse_source:
    if (!ecs_os_strcmp(token, TOK_PARENT)) {
        term.args[0].set = EcsSuperSet;
        term.args[0].relation = EcsChildOf;
        term.args[0].max_depth = 1;
    } else if (!ecs_os_strcmp(token, TOK_SYSTEM)) {
        term.args[0].name = ecs_os_strdup(name);
    } else if (!ecs_os_strcmp(token, TOK_ANY)) {
        term.args[0].set = EcsSelf | EcsSuperSet;
        term.args[0].entity = EcsThis;
        term.args[0].relation = EcsIsA;
    } else if (!ecs_os_strcmp(token, TOK_OWNED)) {
        term.args[0].set = EcsSelf;
        term.args[0].entity = EcsThis;
    } else if (!ecs_os_strcmp(token, TOK_SHARED)) {
        term.args[0].set = EcsSuperSet;
        term.args[0].entity = EcsThis;
        term.args[0].relation = EcsIsA;
    } else if (!ecs_os_strcmp(token, TOK_CASCADE)) {
        term.args[0].set = EcsSuperSet | EcsAll;
        term.args[0].relation = EcsChildOf;
        term.args[0].entity = EcsThis;
        term.oper = EcsOptional;
    } else {
         if (parse_identifier(token, &term.args[0])) {
            ecs_parser_error(name, expr, (ptr - expr), 
                "invalid identifier '%s'", token); 
            return NULL;           
        }
    }

    ptr = skip_space(ptr);
    if (valid_token_start_char(ptr[0])) {
        ptr = parse_token(name, expr, (ptr - expr), ptr, token);
        if (!ptr) {
            return NULL;
        }

        /* Is the next token a role? */
        if (ptr[0] == TOK_BITWISE_OR && ptr[1] != TOK_BITWISE_OR) {
            ptr++;
            goto parse_role;
        }

        /* Is token a trait? (using shorthand notation) */
        if (!ecs_os_strncmp(ptr, TOK_FOR, 3)) {
            term.pred.entity = ECS_PAIR;
            ptr += 3;
            goto parse_trait;
        }        

        /* If not, it's a predicate */
        goto parse_predicate;
    } else {
        ecs_parser_error(name, expr, (ptr - expr), 
            "expected identifier after source");
        return NULL;
    }

parse_role:
    term.role = parse_role(name, expr, (ptr - expr), token);
    if (!term.role) {
        return NULL;
    }

    ptr = skip_space(ptr);

    /* If next token is the source token, this is an empty source */
    if (valid_token_start_char(ptr[0])) {
        ptr = parse_token(name, expr, (ptr - expr), ptr, token);
        if (!ptr) {
            return NULL;
        }

        /* Is token a trait? */
        if (ptr[0] == TOK_TRAIT) {
            ptr ++;
            goto parse_trait;
        }

        /* If not, it's a predicate */
        goto parse_predicate;

    } else if (ptr[0] == TOK_PAREN_OPEN) {
        goto parse_pair;
    } else {
        ecs_parser_error(name, expr, (ptr - expr), 
            "expected identifier after role");
        return NULL;
    }

parse_predicate:
    if (parse_identifier(token, &term.pred)) {
        ecs_parser_error(name, expr, (ptr - expr), 
            "invalid identifier '%s'", token); 
        return NULL;        
    }

    ptr = skip_space(ptr);
    
    if (ptr[0] == TOK_PAREN_OPEN) {
        ptr ++;
        if (ptr[0] == TOK_PAREN_CLOSE) {
            term.args[0].set = EcsNothing;
            ptr ++;
            ptr = skip_space(ptr);
        } else {
            ptr = parse_arguments(
                world, name, expr, (ptr - expr), ptr, token, &term);
        }

        goto parse_done;

    } else if (valid_token_start_char(ptr[0])) {
        ptr = parse_token(name, expr, (ptr - expr), ptr, token);
        if (!ptr) {
            return NULL;
        }

        goto parse_name;
    }

    goto parse_done;

parse_pair:
    ptr = parse_token(name, expr, (ptr - expr), ptr + 1, token);
    if (!ptr) {
        return NULL;
    }

    if (ptr[0] == TOK_AND) {
        ptr ++;
        term.args[0].entity = EcsThis;
        goto parse_pair_predicate;
    } else {
        ecs_parser_error(name, expr, (ptr - expr), 
            "unexpected character '%c'", ptr[0]);
    }

parse_pair_predicate:
    if (parse_identifier(token, &term.pred)) {
        ecs_parser_error(name, expr, (ptr - expr), 
            "invalid identifier '%s'", token); 
        return NULL;            
    }

    ptr = skip_space(ptr);
    if (valid_token_start_char(ptr[0])) {
        ptr = parse_token(name, expr, (ptr - expr), ptr, token);
        if (!ptr) {
            return NULL;
        }

        if (ptr[0] == TOK_PAREN_CLOSE) {
            ptr ++;
            goto parse_pair_object;
        } else {
            ecs_parser_error(name, expr, (ptr - expr), 
                "unexpected character '%c'", ptr[0]);
            return NULL;
        }
    } else if (ptr[0] == TOK_PAREN_CLOSE) {
        /* No object */
        goto parse_done;
    }

parse_pair_object:
    if (parse_identifier(token, &term.args[1])) {
        ecs_parser_error(name, expr, (ptr - expr), 
            "invalid identifier '%s'", token); 
        return NULL;
    }

    ptr = skip_space(ptr);
    goto parse_done; 

parse_trait:
    if (parse_identifier(token, &term.pred)) {
        ecs_parser_error(name, expr, (ptr - expr), 
            "invalid identifier '%s'", token); 
        return NULL;        
    }

    ptr = skip_space(ptr);
    if (valid_token_start_char(ptr[0])) {
        ptr = parse_token(name, expr, (ptr - expr), ptr, token);
        if (!ptr) {
            return NULL;
        }

        /* Can only be an object */
        goto parse_trait_target;
    } else {
        ecs_parser_error(name, expr, (ptr - expr), 
            "expected identifier after trait");
        return NULL;
    }

parse_trait_target:
    parse_identifier(".", &term.args[0]);
    if (parse_identifier(token, &term.args[1])) {
        ecs_parser_error(name, expr, (ptr - expr), 
            "invalid identifier '%s'", token); 
        return NULL;        
    }

    ptr = skip_space(ptr);
    if (valid_token_start_char(ptr[0])) {
        ptr = parse_token(name, expr, (ptr - expr), ptr, token);
        if (!ptr) {
            return NULL;
        }

        /* Can only be a name */
        goto parse_name;
    } else {
        /* If nothing else, parsing of this element is done */
        goto parse_done;
    }

parse_singleton:
    if (parse_identifier(token, &term.pred)) {
        ecs_parser_error(name, expr, (ptr - expr), 
            "invalid identifier '%s'", token); 
        return NULL;        
    }

    parse_identifier(token, &term.args[0]);
    goto parse_done;

parse_name:
    term.name = ecs_os_strdup(token);
    ptr = skip_space(ptr);

parse_done:
    *term_out = term;

    return ptr;
}

char* ecs_parse_term(
    const ecs_world_t *world,
    const char *name,
    const char *expr,
    const char *ptr,
    ecs_term_t *term)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(ptr != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(term != NULL, ECS_INVALID_PARAMETER, NULL);

    ecs_term_id_t *subj = &term->args[0];

    bool prev_or = false;
    if (ptr != expr) {
        /* If this is not the start of the expression, scan back to check if
         * previous token was an OR */
        const char *bptr = ptr - 1;
        do {
            char ch = bptr[0];
            if (isspace(ch)) {
                bptr --;
                continue;
            }

            /* Previous token was not an OR */
            if (ch == TOK_AND) {
                break;
            }

            /* Previous token was an OR */
            if (ch == TOK_OR[0]) {
                prev_or = true;
                break;
            }

            ecs_parser_error(name, expr, (ptr - expr), 
                "invalid preceding token");
            return NULL;
        } while (true);
    }

    ptr = skip_space(ptr);
    if (!ptr[0]) {
        return (char*)ptr;
    }

    if (ptr == expr && !strcmp(expr, "0")) {
        return (char*)&ptr[1];
    }

    int32_t prev_set = subj->set;

    /* Parse next element */
    ptr = parse_term(world, name, ptr, term);
    if (!ptr) {
        ecs_term_fini(term);
        return NULL;
    }

    /* Post-parse consistency checks */

    /* If next token is OR, term is part of an OR expression */
    if (!ecs_os_strncmp(ptr, TOK_OR, 2) || prev_or) {
        /* An OR operator must always follow an AND or another OR */
        if (term->oper != EcsAnd) {
            ecs_parser_error(name, expr, (ptr - expr), 
                "cannot combine || with other operators");
            ecs_term_fini(term);
            return NULL;
        }

        term->oper = EcsOr;
    }

    /* Term must either end in end of expression, AND or OR token */
    if (ptr[0] != TOK_AND && (ptr[0] != TOK_OR[0]) && ptr[0]) {
        ecs_parser_error(name, expr, (ptr - expr), 
            "expected end of expression or next term");
        ecs_term_fini(term);
        return NULL;
    }

    /* If the term just contained a 0, the expression has nothing. Ensure
     * that after the 0 nothing else follows */
    if (!ecs_os_strcmp(term->pred.name, "0")) {
        if (ptr[0]) {
            ecs_parser_error(name, expr, (ptr - expr), 
                "unexpected term after 0"); 
            ecs_term_fini(term);
            return NULL;
        }

        subj->set = EcsNothing;
    }

    /* Cannot combine EcsNothing with operators other than AND */
    if (term->oper != EcsAnd && subj->set == EcsNothing) {
        ecs_parser_error(name, expr, (ptr - expr), 
            "invalid operator for empty source"); 
        ecs_term_fini(term);    
        return NULL;
    }

    /* Verify consistency of OR expression */
    if (prev_or && term->oper == EcsOr) {
        /* Set expressions must be the same for all OR terms */
        if (subj->set != prev_set) {
            ecs_parser_error(name, expr, (ptr - expr), 
                "cannot combine different sources in OR expression");
            ecs_term_fini(term);
            return NULL;
        }

        term->oper = EcsOr;
    }

    /* Automatically assign This if entity is not assigned and the set is
     * nothing */
    if (subj->set != EcsNothing) {
        if (!subj->name) {
            if (!subj->entity) {
                subj->entity = EcsThis;
            }
        }
    }

    if (subj->name && !ecs_os_strcmp(subj->name, "0")) {
        subj->entity = 0;
        subj->set = EcsNothing;
    }

    /* Process role */
    if (term->role == ECS_AND) {
        term->oper = EcsAndFrom;
        term->role = 0;
    } else if (term->role == ECS_OR) {
        term->oper = EcsOrFrom;
        term->role = 0;
    } else if (term->role == ECS_NOT) {
        term->oper = EcsNotFrom;
        term->role = 0;
    }

    if (ptr[0]) {
        if (ptr[0] == ',') {
            ptr ++;
        } else if (ptr[0] == '|') {
            ptr += 2;
        }
    }

    ptr = skip_space(ptr);

    return (char*)ptr;
}

#endif

#ifdef FLECS_DIRECT_ACCESS


/* Prefix with "da" so that they don't conflict with other get_column's */

static
ecs_column_t *da_get_column(
    const ecs_table_t *table,
    int32_t column)
{
    ecs_assert(table != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(column <= table->column_count, ECS_INVALID_PARAMETER, NULL);
    ecs_data_t *data = table->data;
    if (data && data->columns) {
        return &table->data->columns[column];    
    } else {
        return NULL;
    }    
}

static
ecs_column_t *da_get_or_create_column(
    ecs_world_t *world,
    ecs_table_t *table,
    int32_t column)
{
    ecs_column_t *c = da_get_column(table, column);
    if (!c && (!table->data || !table->data->columns)) {
        ecs_data_t *data = ecs_table_get_or_create_data(table);
        ecs_init_data(world, table, data);
        c = da_get_column(table, column);
    }
    ecs_assert(c != NULL, ECS_INTERNAL_ERROR, NULL);
    return c;
}

static
ecs_entity_t* get_entity_array(
    ecs_table_t *table,
    int32_t row)
{
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(table->data != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(table->data->entities != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_entity_t *array = ecs_vector_first(table->data->entities, ecs_entity_t);
    return &array[row];
}

/* -- Public API -- */

ecs_type_t ecs_table_get_type(
    const ecs_table_t *table)
{
    return table->type;
}

ecs_record_t* ecs_record_find(
    ecs_world_t *world,
    ecs_entity_t entity)
{
    ecs_record_t *r = ecs_eis_get(world, entity);
    if (r) {
        return r;
    } else {
        return NULL;
    }
}

ecs_record_t* ecs_record_ensure(
    ecs_world_t *world,
    ecs_entity_t entity)
{
    ecs_record_t *r = ecs_eis_ensure(world, entity);
    ecs_assert(r != NULL, ECS_INTERNAL_ERROR, NULL);
    return r;
}

ecs_record_t ecs_table_insert(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_entity_t entity,
    ecs_record_t *record)
{
    ecs_data_t *data = ecs_table_get_or_create_data(table);
    int32_t index = ecs_table_append(world, table, data, entity, record, true);
    if (record) {
        record->table = table;
        record->row = index + 1;
    }
    return (ecs_record_t){table, index + 1};
}

int32_t ecs_table_find_column(
    const ecs_table_t *table,
    ecs_entity_t component)
{
    ecs_assert(table != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(component != 0, ECS_INVALID_PARAMETER, NULL);
    return ecs_type_index_of(table->type, component);
}

ecs_vector_t* ecs_table_get_column(
    const ecs_table_t *table,
    int32_t column)
{
    ecs_column_t *c = da_get_column(table, column);
    return c ? c->data : NULL;
}

ecs_vector_t* ecs_table_set_column(
    ecs_world_t *world,
    ecs_table_t *table,
    int32_t column,
    ecs_vector_t* vector)
{
    ecs_column_t *c = da_get_or_create_column(world, table, column);
    if (vector) {
        ecs_vector_assert_size(vector, c->size);
    } else {
        ecs_vector_t *entities = ecs_table_get_entities(table);
        if (entities) {
            int32_t count = ecs_vector_count(entities);
            vector = ecs_table_get_column(table, column);
            if (!vector) {
                vector = ecs_vector_new_t(c->size, c->alignment, count);
            } else {
                ecs_vector_set_count_t(&vector, c->size, c->alignment, count);
            }
        }
    }
    c->data = vector;
    
    return vector;
}

ecs_vector_t* ecs_table_get_entities(
    const ecs_table_t *table)
{
    ecs_data_t *data = table->data;
    if (!data) {
        return NULL;
    }

    return data->entities;
}

ecs_vector_t* ecs_table_get_records(
    const ecs_table_t *table)
{
    ecs_data_t *data = table->data;
    if (!data) {
        return NULL;
    }

    return data->record_ptrs;
}

void ecs_table_set_entities(
    ecs_table_t *table,
    ecs_vector_t *entities,
    ecs_vector_t *records)
{
    ecs_vector_assert_size(entities, sizeof(ecs_entity_t));
    ecs_vector_assert_size(records, sizeof(ecs_record_t*));
    ecs_assert(ecs_vector_count(entities) == ecs_vector_count(records), 
        ECS_INVALID_PARAMETER, NULL);

    ecs_data_t *data = table->data;
    if (!data) {
        data = ecs_table_get_or_create_data(table);
        ecs_assert(data != NULL, ECS_INTERNAL_ERROR, NULL);
    }

    data->entities = entities;
    data->record_ptrs = records;
}

void ecs_records_clear(
    ecs_vector_t *records)
{
    int32_t i, count = ecs_vector_count(records);
    ecs_record_t **r = ecs_vector_first(records, ecs_record_t*);

    for (i = 0; i < count; i ++) {
        r[i]->table = NULL;
        if (r[i]->row < 0) {
            r[i]->row = -1;
        } else {
            r[i]->row = 0;
        }
    }
}

void ecs_records_update(
    ecs_world_t *world,
    ecs_vector_t *entities,
    ecs_vector_t *records,
    ecs_table_t *table)
{
    int32_t i, count = ecs_vector_count(records);
    ecs_entity_t *e = ecs_vector_first(entities, ecs_entity_t);
    ecs_record_t **r = ecs_vector_first(records, ecs_record_t*);

    for (i = 0; i < count; i ++) {
        r[i] = ecs_record_ensure(world, e[i]);
        ecs_assert(r[i] != NULL, ECS_INTERNAL_ERROR, NULL);

        r[i]->table = table;
        r[i]->row = i + 1;
    }    
}

void ecs_table_delete_column(
    ecs_world_t *world,
    ecs_table_t *table,
    int32_t column,
    ecs_vector_t *vector)
{
    if (!vector) {
        vector = ecs_table_get_column(table, column);
        if (!vector) {
            return;
        }

        ecs_assert(table->data != NULL, ECS_INTERNAL_ERROR, NULL);
        ecs_assert(table->data->columns != NULL, ECS_INTERNAL_ERROR, NULL);

        table->data->columns[column].data = NULL;
    }

    ecs_column_t *c = da_get_or_create_column(world, table, column);
    ecs_vector_assert_size(vector, c->size);

    ecs_type_info_t *c_info = table->c_info[column];
    ecs_xtor_t dtor;
    if (c_info && (dtor = c_info->lifecycle.dtor)) {
        ecs_entity_t *entities = get_entity_array(table, 0);
        int16_t alignment = c->alignment;
        int32_t count = ecs_vector_count(vector);
        void *ptr = ecs_vector_first_t(vector, c->size, alignment);
        dtor(world, c_info->component, entities, ptr, ecs_to_size_t(c->size), 
            count, c_info->lifecycle.ctx);
    }

    if (c->data == vector) {
        c->data = NULL;
    }

    ecs_vector_free(vector);
}

void* ecs_record_get_column(
    ecs_record_t *r,
    int32_t column,
    size_t c_size)
{
    (void)c_size;
    ecs_table_t *table = r->table;
    ecs_column_t *c = da_get_column(table, column);
    if (!c) {
        return NULL;
    }

    int16_t size = c->size;
    ecs_assert(!ecs_from_size_t(c_size) || ecs_from_size_t(c_size) == c->size, 
        ECS_INVALID_PARAMETER, NULL);

    void *array = ecs_vector_first_t(c->data, c->size, c->alignment);
    bool is_watched;
    int32_t row = ecs_record_to_row(r->row, &is_watched);
    return ECS_OFFSET(array, size * row);
}

void ecs_record_copy_to(
    ecs_world_t *world,
    ecs_record_t *r,
    int32_t column,
    size_t c_size,
    const void *value,
    int32_t count)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(r != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(c_size != 0, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(value != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(count != 0, ECS_INVALID_PARAMETER, NULL);

    ecs_table_t *table = r->table;
    ecs_column_t *c = da_get_or_create_column(world, table, column);
    int16_t size = c->size;
    ecs_assert(!ecs_from_size_t(c_size) || ecs_from_size_t(c_size) == c->size, 
        ECS_INVALID_PARAMETER, NULL);

    int16_t alignment = c->alignment;
    bool is_monitored;
    int32_t row = ecs_record_to_row(r->row, &is_monitored);
    void *ptr = ecs_vector_get_t(c->data, size, alignment, row);
    ecs_assert(ptr != NULL, ECS_INVALID_PARAMETER, NULL);

    ecs_type_info_t *c_info = table->c_info[column];
    ecs_copy_t copy;
    if (c_info && (copy = c_info->lifecycle.copy)) {
        ecs_entity_t *entities = get_entity_array(table, row);
        copy(world, c_info->component, entities, entities, ptr, value, c_size, 
            count, c_info->lifecycle.ctx);
    } else {
        ecs_os_memcpy(ptr, value, size * count);
    }
}

void ecs_record_copy_pod_to(
    ecs_world_t *world,
    ecs_record_t *r,
    int32_t column,
    size_t c_size,
    const void *value,
    int32_t count)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(r != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(c_size != 0, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(value != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(count != 0, ECS_INVALID_PARAMETER, NULL);
    (void)c_size;

    ecs_table_t *table = r->table;
    ecs_column_t *c = da_get_or_create_column(world, table, column);
    int16_t size = c->size;
    ecs_assert(!ecs_from_size_t(c_size) || ecs_from_size_t(c_size) == c->size, 
        ECS_INVALID_PARAMETER, NULL);

    int16_t alignment = c->alignment;
    bool is_monitored;
    int32_t row = ecs_record_to_row(r->row, &is_monitored);
    void *ptr = ecs_vector_get_t(c->data, size, alignment, row);
    ecs_assert(ptr != NULL, ECS_INVALID_PARAMETER, NULL);

    ecs_os_memcpy(ptr, value, size * count);
}

void ecs_record_move_to(
    ecs_world_t *world,
    ecs_record_t *r,
    int32_t column,
    size_t c_size,
    void *value,
    int32_t count)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(r != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(c_size != 0, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(value != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(count != 0, ECS_INVALID_PARAMETER, NULL);

    ecs_table_t *table = r->table;
    ecs_column_t *c = da_get_or_create_column(world, table, column);
    int16_t size = c->size;
    ecs_assert(!ecs_from_size_t(c_size) || ecs_from_size_t(c_size) == c->size, 
        ECS_INVALID_PARAMETER, NULL);

    int16_t alignment = c->alignment;
    bool is_monitored;
    int32_t row = ecs_record_to_row(r->row, &is_monitored);
    void *ptr = ecs_vector_get_t(c->data, size, alignment, row);
    ecs_assert(ptr != NULL, ECS_INVALID_PARAMETER, NULL);

    ecs_type_info_t *c_info = table->c_info[column];
    ecs_move_t move;
    if (c_info && (move = c_info->lifecycle.move)) {
        ecs_entity_t *entities = get_entity_array(table, row);
        move(world, c_info->component, entities, entities, ptr, value, c_size, 
            count, c_info->lifecycle.ctx);
    } else {
        ecs_os_memcpy(ptr, value, size * count);
    }
}

#endif

/* Builtin roles */
const ecs_id_t ECS_CASE =  (ECS_ROLE | (0x7Cull << 56));
const ecs_id_t ECS_SWITCH =  (ECS_ROLE | (0x7Bull << 56));
const ecs_id_t ECS_PAIR =  (ECS_ROLE | (0x7Aull << 56));
const ecs_id_t ECS_OWNED =  (ECS_ROLE | (0x75ull << 56));
const ecs_id_t ECS_DISABLED =  (ECS_ROLE | (0x74ull << 56));

/* Builtin entity ids */
const ecs_entity_t EcsFlecs = (ECS_HI_COMPONENT_ID + 0);
const ecs_entity_t EcsFlecsCore = (ECS_HI_COMPONENT_ID + 1);
const ecs_entity_t EcsWorld = (ECS_HI_COMPONENT_ID + 2);
const ecs_entity_t EcsWildcard = (ECS_HI_COMPONENT_ID + 3);
const ecs_entity_t EcsThis = (ECS_HI_COMPONENT_ID + 4);
const ecs_entity_t EcsTransitive = (ECS_HI_COMPONENT_ID + 5);
const ecs_entity_t EcsFinal = (ECS_HI_COMPONENT_ID + 6);
const ecs_entity_t EcsChildOf = (ECS_HI_COMPONENT_ID + 7);
const ecs_entity_t EcsIsA = (ECS_HI_COMPONENT_ID + 8) ;
const ecs_entity_t EcsModule = (ECS_HI_COMPONENT_ID + 9);
const ecs_entity_t EcsPrefab = (ECS_HI_COMPONENT_ID + 10);
const ecs_entity_t EcsDisabled = (ECS_HI_COMPONENT_ID + 11);
const ecs_entity_t EcsHidden = (ECS_HI_COMPONENT_ID + 12);
const ecs_entity_t EcsOnAdd = (ECS_HI_COMPONENT_ID + 13);
const ecs_entity_t EcsOnRemove = (ECS_HI_COMPONENT_ID + 14);
const ecs_entity_t EcsOnSet = (ECS_HI_COMPONENT_ID + 15);
const ecs_entity_t EcsUnSet = (ECS_HI_COMPONENT_ID + 16);
const ecs_entity_t EcsOnDelete = (ECS_HI_COMPONENT_ID + 17);
const ecs_entity_t EcsOnDeleteObject = (ECS_HI_COMPONENT_ID + 18);
const ecs_entity_t EcsRemove =  (ECS_HI_COMPONENT_ID + 19);
const ecs_entity_t EcsDelete =  (ECS_HI_COMPONENT_ID + 20);
const ecs_entity_t EcsThrow =  (ECS_HI_COMPONENT_ID + 21);
const ecs_entity_t EcsOnDemand = (ECS_HI_COMPONENT_ID + 22);
const ecs_entity_t EcsMonitor = (ECS_HI_COMPONENT_ID + 23);
const ecs_entity_t EcsDisabledIntern = (ECS_HI_COMPONENT_ID + 24);
const ecs_entity_t EcsInactive = (ECS_HI_COMPONENT_ID + 25);
const ecs_entity_t EcsPipeline = (ECS_HI_COMPONENT_ID + 26);
const ecs_entity_t EcsPreFrame = (ECS_HI_COMPONENT_ID + 27);
const ecs_entity_t EcsOnLoad = (ECS_HI_COMPONENT_ID + 28);
const ecs_entity_t EcsPostLoad = (ECS_HI_COMPONENT_ID + 29);
const ecs_entity_t EcsPreUpdate = (ECS_HI_COMPONENT_ID + 30);
const ecs_entity_t EcsOnUpdate = (ECS_HI_COMPONENT_ID + 31);
const ecs_entity_t EcsOnValidate = (ECS_HI_COMPONENT_ID + 32);
const ecs_entity_t EcsPostUpdate = (ECS_HI_COMPONENT_ID + 33);
const ecs_entity_t EcsPreStore = (ECS_HI_COMPONENT_ID + 34);
const ecs_entity_t EcsOnStore = (ECS_HI_COMPONENT_ID + 35);
const ecs_entity_t EcsPostFrame = (ECS_HI_COMPONENT_ID + 36);

/* -- Private functions -- */

const ecs_world_t* ecs_get_world(
    const ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);

    if (world->magic == ECS_WORLD_MAGIC) {
        return world;
    } else {
        return ((ecs_stage_t*)world)->world;
    }
}

const ecs_stage_t* ecs_stage_from_readonly_world(
    const ecs_world_t *world)
{
    ecs_assert(world->magic == ECS_WORLD_MAGIC ||
               world->magic == ECS_STAGE_MAGIC,
               ECS_INTERNAL_ERROR,
               NULL);

    if (world->magic == ECS_WORLD_MAGIC) {
        return &world->stage;

    } else if (world->magic == ECS_STAGE_MAGIC) {
        return (ecs_stage_t*)world;
    }
    
    return NULL;    
}

ecs_stage_t *ecs_stage_from_world(
    ecs_world_t **world_ptr)
{
    ecs_world_t *world = *world_ptr;

    ecs_assert(world->magic == ECS_WORLD_MAGIC ||
               world->magic == ECS_STAGE_MAGIC,
               ECS_INTERNAL_ERROR,
               NULL);

    if (world->magic == ECS_WORLD_MAGIC) {
        ecs_assert(!world->is_readonly, ECS_INVALID_OPERATION, NULL);
        return &world->stage;

    } else if (world->magic == ECS_STAGE_MAGIC) {
        ecs_stage_t *stage = (ecs_stage_t*)world;
        *world_ptr = stage->world;
        return stage;
    }
    
    return NULL;
}

/* Evaluate component monitor. If a monitored entity changed it will have set a
 * flag in one of the world's component monitors. Queries can register 
 * themselves with component monitors to determine whether they need to rematch
 * with tables. */
static
void eval_component_monitor(
    ecs_world_t *world)
{
    ecs_relation_monitor_t *rm = &world->monitors;

    if (!rm->is_dirty) {
        return;
    }

    ecs_map_iter_t it = ecs_map_iter(rm->monitor_sets);
    ecs_monitor_set_t *ms;

    while ((ms = ecs_map_next(&it, ecs_monitor_set_t, NULL))) {
        if (!ms->is_dirty) {
            continue;
        }

        if (ms->monitors) {
            ecs_map_iter_t mit = ecs_map_iter(ms->monitors);
            ecs_monitor_t *m;
            while ((m = ecs_map_next(&mit, ecs_monitor_t, NULL))) {
                if (!m->is_dirty) {
                    continue;
                }

                ecs_vector_each(m->queries, ecs_query_t*, q_ptr, {
                    ecs_query_notify(world, *q_ptr, &(ecs_query_event_t) {
                        .kind = EcsQueryTableRematch
                    });
                });

                m->is_dirty = false;
            }
        }

        ms->is_dirty = false;
    }

    rm->is_dirty = false;
}

void ecs_monitor_mark_dirty(
    ecs_world_t *world,
    ecs_entity_t relation,
    ecs_entity_t id)
{
    ecs_assert(world->monitors.monitor_sets != NULL, ECS_INTERNAL_ERROR, NULL);

    /* Only flag if there are actually monitors registered, so that we
     * don't waste cycles evaluating monitors if there's no interest */
    ecs_monitor_set_t *ms = ecs_map_get(world->monitors.monitor_sets, 
        ecs_monitor_set_t, relation);
    if (ms && ms->monitors) {
        ecs_monitor_t *m = ecs_map_get(ms->monitors, 
            ecs_monitor_t, id);
        if (m) {
            m->is_dirty = true;
            ms->is_dirty = true;
            world->monitors.is_dirty = true;
        }
    }
}

void ecs_monitor_register(
    ecs_world_t *world,
    ecs_entity_t relation,
    ecs_entity_t id,
    ecs_query_t *query)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(id != 0, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(query != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(world->monitors.monitor_sets != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_monitor_set_t *ms = ecs_map_ensure(
        world->monitors.monitor_sets, ecs_monitor_set_t, relation);
    ecs_assert(ms != NULL, ECS_INTERNAL_ERROR, NULL);

    if (!ms->monitors) {
        ms->monitors = ecs_map_new(ecs_monitor_t, 1);
    }

    ecs_monitor_t *m = ecs_map_ensure(ms->monitors, ecs_monitor_t, id);
    ecs_assert(m != NULL, ECS_INTERNAL_ERROR, NULL);        

    ecs_query_t **q = ecs_vector_add(&m->queries, ecs_query_t*);
    *q = query;
}

static
void monitors_init(
    ecs_relation_monitor_t *rm)
{
    rm->monitor_sets = ecs_map_new(ecs_monitor_t, 0);
    rm->is_dirty = false;
}

static
void monitors_fini(
    ecs_relation_monitor_t *rm)
{
    ecs_map_iter_t it = ecs_map_iter(rm->monitor_sets);
    ecs_monitor_set_t *ms;

    while ((ms = ecs_map_next(&it, ecs_monitor_set_t, NULL))) {
        if (ms->monitors) {
            ecs_map_iter_t mit = ecs_map_iter(ms->monitors);
            ecs_monitor_t *m;
            while ((m = ecs_map_next(&mit, ecs_monitor_t, NULL))) {
                ecs_vector_free(m->queries);
            }

            ecs_map_free(ms->monitors);
        }
    }

    ecs_map_free(rm->monitor_sets);
}

static
void init_store(
    ecs_world_t *world) 
{
    ecs_os_memset(&world->store, 0, ECS_SIZEOF(ecs_store_t));
    
    /* Initialize entity index */
    world->store.entity_index = ecs_sparse_new(ecs_record_t);
    ecs_sparse_set_id_source(world->store.entity_index, &world->stats.last_id);

    /* Initialize root table */
    world->store.tables = ecs_sparse_new(ecs_table_t);

    /* Initialize table map */
    world->store.table_map = ecs_map_new(ecs_vector_t*, 8);

    /* Initialize one root table per stage */
    ecs_init_root_table(world);
}

static
void clean_tables(
    ecs_world_t *world)
{
    int32_t i, count = ecs_sparse_count(world->store.tables);

    for (i = 0; i < count; i ++) {
        ecs_table_t *t = ecs_sparse_get(world->store.tables, ecs_table_t, i);
        ecs_table_free(world, t);
    }

    /* Clear the root table */
    if (count) {
        ecs_table_reset(world, &world->store.root);
    }
}

static
void fini_store(ecs_world_t *world) {
    clean_tables(world);
    ecs_sparse_free(world->store.tables);
    ecs_table_free(world, &world->store.root);
    ecs_sparse_free(world->store.entity_index);

    ecs_map_iter_t it = ecs_map_iter(world->store.table_map);
    ecs_vector_t *tables;
    while ((tables = ecs_map_next_ptr(&it, ecs_vector_t*, NULL))) {
        ecs_vector_free(tables);
    }
    
    ecs_map_free(world->store.table_map);
}

/* -- Public functions -- */

ecs_world_t *ecs_mini(void) {
    ecs_os_init();

    ecs_trace_1("bootstrap");
    ecs_log_push();

    if (!ecs_os_has_heap()) {
        ecs_abort(ECS_MISSING_OS_API, NULL);
    }

    if (!ecs_os_has_threading()) {
        ecs_trace_1("threading not available");
    }

    if (!ecs_os_has_time()) {
        ecs_trace_1("time management not available");
    }

    ecs_world_t *world = ecs_os_calloc(sizeof(ecs_world_t));
    ecs_assert(world != NULL, ECS_OUT_OF_MEMORY, NULL);

    world->magic = ECS_WORLD_MAGIC;
    world->fini_actions = NULL; 

    world->type_info = ecs_sparse_new(ecs_type_info_t);
    world->id_index = ecs_map_new(ecs_id_record_t, 8);
    world->id_triggers = ecs_map_new(ecs_id_trigger_t, 8);

    world->aliases = NULL;

    world->queries = ecs_sparse_new(ecs_query_t);
    world->triggers = ecs_sparse_new(ecs_trigger_t);
    world->fini_tasks = ecs_vector_new(ecs_entity_t, 0);
    world->name_prefix = NULL;

    monitors_init(&world->monitors);

    world->type_handles = ecs_map_new(ecs_entity_t, 0);
    world->on_activate_components = ecs_map_new(ecs_on_demand_in_t, 0);
    world->on_enable_components = ecs_map_new(ecs_on_demand_in_t, 0);

    world->worker_stages = NULL;
    world->workers_waiting = 0;
    world->workers_running = 0;
    world->quit_workers = false;
    world->is_readonly = false;
    world->is_fini = false;
    world->measure_frame_time = false;
    world->measure_system_time = false;
    world->should_quit = false;
    world->locking_enabled = false;
    world->pipeline = 0;

    world->frame_start_time = (ecs_time_t){0, 0};
    if (ecs_os_has_time()) {
        ecs_os_get_time(&world->world_start_time);
    }

    world->stats.target_fps = 0;
    world->stats.last_id = 0;

    world->stats.delta_time_raw = 0;
    world->stats.delta_time = 0;
    world->stats.time_scale = 1.0;
    world->stats.frame_time_total = 0;
    world->stats.system_time_total = 0;
    world->stats.merge_time_total = 0;
    world->stats.world_time_total = 0;
    world->stats.frame_count_total = 0;
    world->stats.merge_count_total = 0;
    world->stats.systems_ran_frame = 0;
    world->stats.pipeline_build_count_total = 0;
    
    world->range_check_enabled = true;

    world->fps_sleep = 0;

    world->context = NULL;

    world->arg_fps = 0;
    world->arg_threads = 0;

    ecs_stage_init(world, &world->stage);
    ecs_set_stages(world, 1);

    init_store(world);

    ecs_bootstrap(world);

    ecs_log_pop();

    return world;
}

ecs_world_t *ecs_init(void) {
    ecs_world_t *world = ecs_mini();

#ifdef FLECS_MODULE_H
    ecs_trace_1("import builtin modules");
    ecs_log_push();
#ifdef FLECS_SYSTEM_H
    ECS_IMPORT(world, FlecsSystem);
#endif
#ifdef FLECS_PIPELINE_H
    ECS_IMPORT(world, FlecsPipeline);
#endif
#ifdef FLECS_TIMER_H
    ECS_IMPORT(world, FlecsTimer);
#endif
    ecs_log_pop();
#endif

    return world;
}

#define ARG(short, long, action)\
    if (i < argc) {\
        if (argv[i][0] == '-') {\
            if (argv[i][1] == '-') {\
                if (long && !strcmp(&argv[i][2], long ? long : "")) {\
                    action;\
                    parsed = true;\
                }\
            } else {\
                if (short && argv[i][1] == short) {\
                    action;\
                    parsed = true;\
                }\
            }\
        }\
    }

ecs_world_t* ecs_init_w_args(
    int argc,
    char *argv[])
{
    (void)argc;
    (void)argv;
    return ecs_init();
}

void ecs_quit(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_stage_from_world(&world);
    world->should_quit = true;
}

bool ecs_should_quit(
    const ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    world = ecs_get_world(world);
    return world->should_quit;
}

static
void on_demand_in_map_fini(
    ecs_map_t *map)
{
    ecs_map_iter_t it = ecs_map_iter(map);
    ecs_on_demand_in_t *elem;

    while ((elem = ecs_map_next(&it, ecs_on_demand_in_t, NULL))) {
        ecs_vector_free(elem->systems);
    }

    ecs_map_free(map);
}

static
void ctor_init_zero(
    ecs_world_t *world,
    ecs_entity_t component,
    const ecs_entity_t *entity_ptr,
    void *ptr,
    size_t size,
    int32_t count,
    void *ctx)
{
    (void)world;
    (void)component;
    (void)entity_ptr;
    (void)ctx;
    ecs_os_memset(ptr, 0, ecs_from_size_t(size) * count);
}

void ecs_notify_tables(
    ecs_world_t *world,
    ecs_id_t id,
    ecs_table_event_t *event)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);

    /* If no id is specified, broadcast to all tables */
    if (!id) {
        ecs_sparse_t *tables = world->store.tables;
        int32_t i, count = ecs_sparse_count(tables);
        for (i = 0; i < count; i ++) {
            ecs_table_t *table = ecs_sparse_get(tables, ecs_table_t, i);
            ecs_table_notify(world, table, event);
        }

    /* If id is specified, only broadcast to tables with id */
    } else {
        ecs_id_record_t *r = ecs_get_id_record(world, id);
        if (!r) {
            return;
        }

        ecs_table_record_t *tr;
        ecs_map_iter_t it = ecs_map_iter(r->table_index);
        while ((tr = ecs_map_next(&it, ecs_table_record_t, NULL))) {
            ecs_table_notify(world, tr->table, event);
        }
    }
}

void ecs_set_component_actions_w_id(
    ecs_world_t *world,
    ecs_entity_t component,
    EcsComponentLifecycle *lifecycle)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_stage_from_world(&world);

#ifndef NDEBUG
    const EcsComponent *component_ptr = ecs_get(world, component, EcsComponent);

    /* Cannot register lifecycle actions for things that aren't a component */
    ecs_assert(component_ptr != NULL, ECS_INVALID_PARAMETER, NULL);

    /* Cannot register lifecycle actions for components with size 0 */
    ecs_assert(component_ptr->size != 0, ECS_INVALID_PARAMETER, NULL);
#endif

    ecs_type_info_t *c_info = ecs_get_or_create_c_info(world, component);
    ecs_assert(c_info != NULL, ECS_INTERNAL_ERROR, NULL);

    if (c_info->lifecycle_set) {
        ecs_assert(c_info->component == component, ECS_INTERNAL_ERROR, NULL);
        ecs_assert(c_info->lifecycle.ctor == lifecycle->ctor, 
            ECS_INCONSISTENT_COMPONENT_ACTION, NULL);
        ecs_assert(c_info->lifecycle.dtor == lifecycle->dtor, 
            ECS_INCONSISTENT_COMPONENT_ACTION, NULL);
        ecs_assert(c_info->lifecycle.copy == lifecycle->copy, 
            ECS_INCONSISTENT_COMPONENT_ACTION, NULL);
        ecs_assert(c_info->lifecycle.move == lifecycle->move, 
            ECS_INCONSISTENT_COMPONENT_ACTION, NULL);
    } else {
        c_info->component = component;
        c_info->lifecycle = *lifecycle;
        c_info->lifecycle_set = true;

        /* If no constructor is set, invoking any of the other lifecycle actions 
         * is not safe as they will potentially access uninitialized memory. For 
         * ease of use, if no constructor is specified, set a default one that 
         * initializes the component to 0. */
        if (!lifecycle->ctor && (lifecycle->dtor || lifecycle->copy || lifecycle->move)) {
            c_info->lifecycle.ctor = ctor_init_zero;   
        }

        /* Broadcast to all tables since we need to register a ctor for every
         * table that uses the component as itself, as predicate or as object.
         * The latter is what makes selecting the right set of tables complex,
         * as it depends on the predicate of a pair whether the object is used
         * as the component type or not. 
         * A more selective approach requires a more expressive notification
         * framework. */
        ecs_notify_tables(world, 0, &(ecs_table_event_t) {
            .kind = EcsTableComponentInfo,
            .component = component
        });
    }
}

bool ecs_component_has_actions(
    const ecs_world_t *world,
    ecs_entity_t component)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    world = ecs_get_world(world);

    const ecs_type_info_t *c_info = ecs_get_c_info(world, component);
    return (c_info != NULL) && c_info->lifecycle_set;
}

void ecs_atfini(
    ecs_world_t *world,
    ecs_fini_action_t action,
    void *ctx)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);

    ecs_assert(action != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_action_elem_t *elem = ecs_vector_add(&world->fini_actions, 
        ecs_action_elem_t);
    ecs_assert(elem != NULL, ECS_INTERNAL_ERROR, NULL);

    elem->action = action;
    elem->ctx = ctx;
}

void ecs_run_post_frame(
    ecs_world_t *world,
    ecs_fini_action_t action,
    void *ctx)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(action != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_stage_t *stage = ecs_stage_from_world(&world);

    ecs_action_elem_t *elem = ecs_vector_add(&stage->post_frame_actions, 
        ecs_action_elem_t);
    ecs_assert(elem != NULL, ECS_INTERNAL_ERROR, NULL);

    elem->action = action;
    elem->ctx = ctx;    
}

/* Unset data in tables */
static
void fini_unset_tables(
    ecs_world_t *world)
{
    int32_t i, count = ecs_sparse_count(world->store.tables);
    for (i = 0; i < count; i ++) {
        ecs_table_t *table = ecs_sparse_get(world->store.tables, ecs_table_t, i);
        ecs_table_unset(world, table);
    }
}

/* Invoke fini actions */
static
void fini_actions(
    ecs_world_t *world)
{
    ecs_vector_each(world->fini_actions, ecs_action_elem_t, elem, {
        elem->action(world, elem->ctx);
    });

    ecs_vector_free(world->fini_actions);
}

/* Cleanup component lifecycle callbacks & systems */
static
void fini_component_lifecycle(
    ecs_world_t *world)
{
    int32_t i, count = ecs_sparse_count(world->type_info);
    for (i = 0; i < count; i ++) {
        ecs_type_info_t *type_info = ecs_sparse_get(
            world->type_info, ecs_type_info_t, i);
        ecs_assert(type_info != NULL, ECS_INTERNAL_ERROR, NULL);

        ecs_vector_free(type_info->on_add);
        ecs_vector_free(type_info->on_remove);
    }

    ecs_sparse_free(world->type_info);
}

/* Cleanup queries */
static
void fini_queries(
    ecs_world_t *world)
{
    int32_t i, count = ecs_sparse_count(world->queries);
    for (i = 0; i < count; i ++) {
        ecs_query_t *query = ecs_sparse_get(world->queries, ecs_query_t, 0);
        ecs_query_fini(query);
    }
    ecs_sparse_free(world->queries);
}

/* Cleanup stages */
static
void fini_stages(
    ecs_world_t *world)
{
    ecs_stage_deinit(world, &world->stage);
    ecs_set_stages(world, 0);
}

/* Cleanup id index */
static
void fini_id_index(
    ecs_world_t *world)
{
    ecs_map_iter_t it = ecs_map_iter(world->id_index);
    ecs_id_record_t *r;
    while ((r = ecs_map_next(&it, ecs_id_record_t, NULL))) {
        ecs_map_free(r->table_index);
    }

    ecs_map_free(world->id_index);
}

static
void fini_id_triggers(
    ecs_world_t *world)
{
    ecs_map_iter_t it = ecs_map_iter(world->id_triggers);
    ecs_id_trigger_t *t;
    while ((t = ecs_map_next(&it, ecs_id_trigger_t, NULL))) {
        ecs_map_free(t->on_add_triggers);
        ecs_map_free(t->on_remove_triggers);
    }

    ecs_map_free(world->id_triggers);

    ecs_sparse_free(world->triggers);
}

/* Cleanup aliases */
static
void fini_aliases(
    ecs_world_t *world)
{
    int32_t i, count = ecs_vector_count(world->aliases);
    ecs_alias_t *aliases = ecs_vector_first(world->aliases, ecs_alias_t);

    for (i = 0; i < count; i ++) {
        ecs_os_free(aliases[i].name);
    }

    ecs_vector_free(world->aliases);
}

/* Cleanup misc structures */
static
void fini_misc(
    ecs_world_t *world)
{
    on_demand_in_map_fini(world->on_activate_components);
    on_demand_in_map_fini(world->on_enable_components);
    ecs_map_free(world->type_handles);
    ecs_vector_free(world->fini_tasks);
    monitors_fini(&world->monitors);
}

/* The destroyer of worlds */
int ecs_fini(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!world->is_readonly, ECS_INVALID_OPERATION, NULL);
    ecs_assert(!world->is_fini, ECS_INVALID_OPERATION, NULL);

    world->is_fini = true;

    fini_unset_tables(world);

    fini_actions(world);    

    if (world->locking_enabled) {
        ecs_os_mutex_free(world->mutex);
    }

    fini_stages(world);

    fini_store(world);

    fini_component_lifecycle(world);

    fini_queries(world);

    fini_id_index(world);

    fini_id_triggers(world);

    fini_aliases(world);

    fini_misc(world);

    /* In case the application tries to use the memory of the freed world, this
     * will trigger an assert */
    world->magic = 0;

    ecs_increase_timer_resolution(0);

    /* End of the world */
    ecs_os_free(world);

    ecs_os_fini(); 

    return 0;
}

void ecs_dim(
    ecs_world_t *world,
    int32_t entity_count)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);    
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_PARAMETER, NULL);
    ecs_eis_set_size(world, entity_count + ECS_HI_COMPONENT_ID);
}

void ecs_eval_component_monitors(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);    
    eval_component_monitor(world);
}

void ecs_measure_frame_time(
    ecs_world_t *world,
    bool enable)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);
    ecs_assert(ecs_os_has_time(), ECS_MISSING_OS_API, NULL);

    if (world->stats.target_fps == 0.0f || enable) {
        world->measure_frame_time = enable;
    }
}

void ecs_measure_system_time(
    ecs_world_t *world,
    bool enable)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);
    ecs_assert(ecs_os_has_time(), ECS_MISSING_OS_API, NULL);
    world->measure_system_time = enable;
}

/* Increase timer resolution based on target fps */
static 
void set_timer_resolution(
    FLECS_FLOAT fps)
{
    if(fps >= 60.0f) ecs_increase_timer_resolution(1);
    else ecs_increase_timer_resolution(0);
}

void ecs_set_target_fps(
    ecs_world_t *world,
    FLECS_FLOAT fps)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);
    ecs_assert(ecs_os_has_time(), ECS_MISSING_OS_API, NULL);

    if (!world->arg_fps) {
        ecs_measure_frame_time(world, true);
        world->stats.target_fps = fps;
        set_timer_resolution(fps);
    }
}

void* ecs_get_context(
    const ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);    
    world = ecs_get_world(world);
    return world->context;
}

void ecs_set_context(
    ecs_world_t *world,
    void *context)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);    
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);
    world->context = context;
}

void ecs_set_entity_range(
    ecs_world_t *world,
    ecs_entity_t id_start,
    ecs_entity_t id_end)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);    
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);
    ecs_assert(!id_end || id_end > id_start, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!id_end || id_end > world->stats.last_id, ECS_INVALID_PARAMETER, NULL);

    if (world->stats.last_id < id_start) {
        world->stats.last_id = id_start - 1;
    }

    world->stats.min_id = id_start;
    world->stats.max_id = id_end;
}

bool ecs_enable_range_check(
    ecs_world_t *world,
    bool enable)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);    
    bool old_value = world->range_check_enabled;
    world->range_check_enabled = enable;
    return old_value;
}

int32_t ecs_get_threads(
    ecs_world_t *world)
{
    return ecs_vector_count(world->worker_stages);
}

bool ecs_enable_locking(
    ecs_world_t *world,
    bool enable)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);    
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);

    if (enable) {
        if (!world->locking_enabled) {
            world->mutex = ecs_os_mutex_new();
            world->thr_sync = ecs_os_mutex_new();
            world->thr_cond = ecs_os_cond_new();
        }
    } else {
        if (world->locking_enabled) {
            ecs_os_mutex_free(world->mutex);
            ecs_os_mutex_free(world->thr_sync);
            ecs_os_cond_free(world->thr_cond);
        }
    }

    bool old = world->locking_enabled;
    world->locking_enabled = enable;
    return old;
}

void ecs_lock(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);    
    ecs_assert(world->locking_enabled, ECS_INVALID_PARAMETER, NULL);
    ecs_os_mutex_lock(world->mutex);
}

void ecs_unlock(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);    
    ecs_assert(world->locking_enabled, ECS_INVALID_PARAMETER, NULL);
    ecs_os_mutex_unlock(world->mutex);
}

void ecs_begin_wait(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);    
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);
    ecs_assert(world->locking_enabled, ECS_INVALID_PARAMETER, NULL);
    ecs_os_mutex_lock(world->thr_sync);
    ecs_os_cond_wait(world->thr_cond, world->thr_sync);
}

void ecs_end_wait(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);    
    ecs_assert(world->locking_enabled, ECS_INVALID_PARAMETER, NULL);
    ecs_os_mutex_unlock(world->thr_sync);
}

const ecs_type_info_t * ecs_get_c_info(
    const ecs_world_t *world,
    ecs_entity_t component)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);   

    ecs_assert(component != 0, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(!(component & ECS_ROLE_MASK), ECS_INTERNAL_ERROR, NULL);

    return ecs_sparse_get_sparse(world->type_info, ecs_type_info_t, component);
}

ecs_type_info_t * ecs_get_or_create_c_info(
    ecs_world_t *world,
    ecs_entity_t component)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);  

    const ecs_type_info_t *c_info = ecs_get_c_info(world, component);
    ecs_type_info_t *c_info_mut = NULL;
    if (!c_info) {
        c_info_mut = ecs_sparse_ensure(
            world->type_info, ecs_type_info_t, component);
        ecs_assert(c_info_mut != NULL, ECS_INTERNAL_ERROR, NULL);         
    } else {
        c_info_mut = (ecs_type_info_t*)c_info;
    }

    return c_info_mut;
}

static
FLECS_FLOAT insert_sleep(
    ecs_world_t *world,
    ecs_time_t *stop)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);  

    ecs_time_t start = *stop;
    FLECS_FLOAT delta_time = (FLECS_FLOAT)ecs_time_measure(stop);

    if (world->stats.target_fps == (FLECS_FLOAT)0.0) {
        return delta_time;
    }

    FLECS_FLOAT target_delta_time = 
        ((FLECS_FLOAT)1.0 / (FLECS_FLOAT)world->stats.target_fps);

    /* Calculate the time we need to sleep by taking the measured delta from the
     * previous frame, and subtracting it from target_delta_time. */
    FLECS_FLOAT sleep = target_delta_time - delta_time;

    /* Pick a sleep interval that is 20 times lower than the time one frame
     * should take. This means that this function at most iterates 20 times in
     * a busy loop */
    FLECS_FLOAT sleep_time = sleep / (FLECS_FLOAT)4.0;

    do {
        /* Only call sleep when sleep_time is not 0. On some platforms, even
         * a sleep with a timeout of 0 can cause stutter. */
        if (sleep_time != 0) {
            ecs_sleepf((double)sleep_time);
        }

        ecs_time_t now = start;
        delta_time = (FLECS_FLOAT)ecs_time_measure(&now);
    } while ((target_delta_time - delta_time) > 
        (sleep_time / (FLECS_FLOAT)2.0));

    return delta_time;
}

static
FLECS_FLOAT start_measure_frame(
    ecs_world_t *world,
    FLECS_FLOAT user_delta_time)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);  

    FLECS_FLOAT delta_time = 0;

    if (world->measure_frame_time || (user_delta_time == 0)) {
        ecs_time_t t = world->frame_start_time;
        do {
            if (world->frame_start_time.sec) {
                delta_time = insert_sleep(world, &t);

                ecs_time_measure(&t);
            } else {
                ecs_time_measure(&t);
                if (world->stats.target_fps != 0) {
                    delta_time = (FLECS_FLOAT)1.0 / world->stats.target_fps;
                } else {
                    /* Best guess */
                    delta_time = (FLECS_FLOAT)1.0 / (FLECS_FLOAT)60.0; 
                }
            }
        
        /* Keep trying while delta_time is zero */
        } while (delta_time == 0);

        world->frame_start_time = t;  

        /* Keep track of total time passed in world */
        world->stats.world_time_total_raw += (FLECS_FLOAT)delta_time;
    }

    return (FLECS_FLOAT)delta_time;
}

static
void stop_measure_frame(
    ecs_world_t* world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);  

    if (world->measure_frame_time) {
        ecs_time_t t = world->frame_start_time;
        world->stats.frame_time_total += (FLECS_FLOAT)ecs_time_measure(&t);
    }
}

FLECS_FLOAT ecs_frame_begin(
    ecs_world_t *world,
    FLECS_FLOAT user_delta_time)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);
    ecs_assert(world->is_readonly == false, ECS_INVALID_OPERATION, NULL);

    ecs_assert(user_delta_time != 0 || ecs_os_has_time(), ECS_MISSING_OS_API, "get_time");

    if (world->locking_enabled) {
        ecs_lock(world);
    }

    /* Start measuring total frame time */
    FLECS_FLOAT delta_time = start_measure_frame(world, user_delta_time);
    if (user_delta_time == 0) {
        user_delta_time = delta_time;
    }  

    world->stats.delta_time_raw = user_delta_time;
    world->stats.delta_time = user_delta_time * world->stats.time_scale;

    /* Keep track of total scaled time passed in world */
    world->stats.world_time_total += world->stats.delta_time;

    ecs_eval_component_monitors(world);

    return user_delta_time;
}

void ecs_frame_end(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);
    ecs_assert(world->is_readonly == false, ECS_INVALID_OPERATION, NULL);

    world->stats.frame_count_total ++;

    ecs_vector_each(world->worker_stages, ecs_stage_t, stage, {
        ecs_stage_merge_post_frame(world, stage);
    });        

    if (world->locking_enabled) {
        ecs_unlock(world);

        ecs_os_mutex_lock(world->thr_sync);
        ecs_os_cond_broadcast(world->thr_cond);
        ecs_os_mutex_unlock(world->thr_sync);
    }

    stop_measure_frame(world);
}

const ecs_world_info_t* ecs_get_world_info(
    const ecs_world_t *world)
{
    world = ecs_get_world(world);
    return &world->stats;
}

void ecs_notify_queries(
    ecs_world_t *world,
    ecs_query_event_t *event)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL); 

    int32_t i, count = ecs_sparse_count(world->queries);
    for (i = 0; i < count; i ++) {
        ecs_query_notify(world, 
            ecs_sparse_get(world->queries, ecs_query_t, i), event);
    }    
}

void ecs_delete_table(
    ecs_world_t *world,
    ecs_table_t *table)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL); 

    /* Notify queries that table is to be removed */
    ecs_notify_queries(
        world, &(ecs_query_event_t){
            .kind = EcsQueryTableUnmatch,
            .table = table
        });

    uint64_t id = table->id;

    /* Free resources associated with table */
    ecs_table_free(world, table);

    /* Remove table from sparse set */
    ecs_assert(id != 0, ECS_INTERNAL_ERROR, NULL);
    ecs_sparse_remove(world->store.tables, id);
}

static
void register_table_for_id(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_id_t id,
    int32_t column)
{
    ecs_id_record_t *r = ecs_ensure_id_record(world, id);
    ecs_assert(r != NULL, ECS_INTERNAL_ERROR, NULL);

    if (!r->table_index) {
        r->table_index = ecs_map_new(ecs_table_record_t, 1);
    }

    ecs_table_record_t *tr = ecs_map_ensure(
        r->table_index, ecs_table_record_t, table->id);

    /* A table can be registered for the same entity multiple times if this is
     * a trait. In that case make sure the column with the first occurrence is
     * registered with the index */
    if (!tr->table || column < tr->column) {
        tr->table = table;
        tr->column = column;
    }

    /* Set flags if triggers are registered for table */
    if (!(table->flags & EcsTableIsDisabled)) {
        if (ecs_triggers_get(world, id, EcsOnAdd)) {
            table->flags |= EcsTableHasOnAdd;
        }
        if (ecs_triggers_get(world, id, EcsOnRemove)) {
            table->flags |= EcsTableHasOnRemove;
        }
    }
}

static
void unregister_table_for_id(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_id_t id)
{
    ecs_id_record_t *r = ecs_get_id_record(world, id);
    if (!r || !r->table_index) {
        return;
    }

    ecs_map_remove(r->table_index, table->id);
    if (!ecs_map_count(r->table_index)) {
        ecs_clear_id_record(world, id);
    }
}

static
void do_register_id(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_id_t id,
    int32_t column,
    bool unregister)
{
    if (unregister) {
        unregister_table_for_id(world, table, id);
    } else {
        register_table_for_id(world, table, id, column);
    }
}

static
void do_register_each_id(
    ecs_world_t *world,
    ecs_table_t *table,
    bool unregister)
{
    int32_t i, count = ecs_vector_count(table->type);
    ecs_id_t *ids = ecs_vector_first(table->type, ecs_id_t);
    bool has_childof = false;
    
    for (i = 0; i < count; i ++) {
        ecs_entity_t id = ids[i];

        /* This check ensures that legacy INSTANCEOF works */
        if (ECS_HAS_RELATION(id, EcsIsA)) {
            id = ecs_pair(EcsIsA, ECS_PAIR_OBJECT(id));
        }

        /* This check ensures that legacy CHILDOF works */
        if (ECS_HAS_RELATION(id, EcsChildOf)) {
            id = ecs_pair(EcsChildOf, ECS_PAIR_OBJECT(id));
            has_childof = true;
        } 

        do_register_id(world, table, id, i, unregister);

        if (ECS_HAS_ROLE(id, PAIR)) {
            ecs_entity_t pred_w_wildcard = ecs_pair(
                ECS_PAIR_RELATION(id), EcsWildcard);       
            do_register_id(world, table, pred_w_wildcard, i, unregister);

            ecs_entity_t obj_w_wildcard = ecs_pair(
                EcsWildcard, ECS_PAIR_OBJECT(id));
            do_register_id(world, table, obj_w_wildcard, i, unregister);

            ecs_entity_t all_wildcard = ecs_pair(EcsWildcard, EcsWildcard);
            do_register_id(world, table, all_wildcard, i, unregister);

            if (!unregister) {
                ecs_set_watch(world, ecs_pair_relation(world, id));
                ecs_set_watch(world, ecs_pair_object(world, id));
            }
        } else {
            do_register_id(world, table, EcsWildcard, i, unregister);

            if (!unregister) {
                ecs_set_watch(world, id);
            }
        }
    }

    if (!has_childof) {
        do_register_id(world, table, ecs_pair(EcsChildOf, 0), 0, unregister);
    }
}

void ecs_register_table(
    ecs_world_t *world,
    ecs_table_t *table)
{
    do_register_each_id(world, table, false);
}

void ecs_unregister_table(
    ecs_world_t *world,
    ecs_table_t *table)
{
    do_register_each_id(world, table, true);
}

ecs_id_record_t* ecs_ensure_id_record(
    const ecs_world_t *world,
    ecs_id_t id)
{
    return ecs_map_ensure(world->id_index, ecs_id_record_t, id);
}

ecs_id_record_t* ecs_get_id_record(
    const ecs_world_t *world,
    ecs_id_t id)
{
    return ecs_map_get(world->id_index, ecs_id_record_t, id);
}

void ecs_clear_id_record(
    const ecs_world_t *world,
    ecs_id_t id)    
{
    ecs_id_record_t *r = ecs_get_id_record(world, id);
    if (!r) {
        return;
    }

    ecs_map_free(r->table_index);
    ecs_map_remove(world->id_index, id);
}

static
ecs_switch_header_t *get_header(
    const ecs_switch_t *sw,
    uint64_t value)
{
    if (value == 0) {
        return NULL;
    }

    value = (uint32_t)value;

    ecs_assert(value >= sw->min, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(value <= sw->max, ECS_INTERNAL_ERROR, NULL);

    uint64_t index = value - sw->min;

    return &sw->headers[index];
}

static
void remove_node(
    ecs_switch_header_t *hdr,
    ecs_switch_node_t *nodes,
    ecs_switch_node_t *node,
    int32_t element)
{    
    /* The node is currently assigned to a value */
    if (hdr->element == element) {
        ecs_assert(node->prev == -1, ECS_INVALID_PARAMETER, NULL);
        /* If this is the first node, update the header */
        hdr->element = node->next;
    } else {
        /* If this is not the first node, update the previous node to the 
         * removed node's next ptr */
        ecs_assert(node->prev != -1, ECS_INVALID_PARAMETER, NULL);
        ecs_switch_node_t *prev_node = &nodes[node->prev];
        prev_node->next = node->next;
    }

    int32_t next = node->next;
    if (next != -1) {
        ecs_assert(next >= 0, ECS_INVALID_PARAMETER, NULL);
        /* If this is not the last node, update the next node to point to the
         * removed node's prev ptr */
        ecs_switch_node_t *next_node = &nodes[next];
        next_node->prev = node->prev;
    }

    /* Decrease count of current header */
    hdr->count --;
    ecs_assert(hdr->count >= 0, ECS_INTERNAL_ERROR, NULL);
}

ecs_switch_t* ecs_switch_new(
    uint64_t min, 
    uint64_t max,
    int32_t elements)
{
    ecs_assert(min != max, ECS_INVALID_PARAMETER, NULL);

    /* Min must be larger than 0, as 0 is an invalid entity id, and should
     * therefore never occur as case id */
    ecs_assert(min > 0, ECS_INVALID_PARAMETER, NULL);

    ecs_switch_t *result = ecs_os_malloc(ECS_SIZEOF(ecs_switch_t));
    result->min = (uint32_t)min;
    result->max = (uint32_t)max;

    int32_t count = (int32_t)(max - min) + 1;
    result->headers = ecs_os_calloc(ECS_SIZEOF(ecs_switch_header_t) * count);
    result->nodes = ecs_vector_new(ecs_switch_node_t, elements);
    result->values = ecs_vector_new(uint64_t, elements);

    int64_t i;
    for (i = 0; i < count; i ++) {
        result->headers[i].element = -1;
        result->headers[i].count = 0;
    }

    ecs_switch_node_t *nodes = ecs_vector_first(
        result->nodes, ecs_switch_node_t);
    uint64_t *values = ecs_vector_first(
        result->values, uint64_t);        

    for (i = 0; i < elements; i ++) {
        nodes[i].prev = -1;
        nodes[i].next = -1;
        values[i] = 0;
    }

    return result;
}

void ecs_switch_free(
    ecs_switch_t *sw)
{
    ecs_os_free(sw->headers);
    ecs_vector_free(sw->nodes);
    ecs_vector_free(sw->values);
    ecs_os_free(sw);
}

void ecs_switch_add(
    ecs_switch_t *sw)
{
    ecs_switch_node_t *node = ecs_vector_add(&sw->nodes, ecs_switch_node_t);
    uint64_t *value = ecs_vector_add(&sw->values, uint64_t);
    node->prev = -1;
    node->next = -1;
    *value = 0;
}

void ecs_switch_set_count(
    ecs_switch_t *sw,
    int32_t count)
{
    int32_t old_count = ecs_vector_count(sw->nodes);
    if (old_count == count) {
        return;
    }

    ecs_vector_set_count(&sw->nodes, ecs_switch_node_t, count);
    ecs_vector_set_count(&sw->values, uint64_t, count);

    ecs_switch_node_t *nodes = ecs_vector_first(sw->nodes, ecs_switch_node_t);
    uint64_t *values = ecs_vector_first(sw->values, uint64_t);

    int32_t i;
    for (i = old_count; i < count; i ++) {
        ecs_switch_node_t *node = &nodes[i];
        node->prev = -1;
        node->next = -1;
        values[i] = 0;
    }
}

void ecs_switch_ensure(
    ecs_switch_t *sw,
    int32_t count)
{
    int32_t old_count = ecs_vector_count(sw->nodes);
    if (old_count >= count) {
        return;
    }

    ecs_switch_set_count(sw, count);
}

void ecs_switch_addn(
    ecs_switch_t *sw,
    int32_t count)
{
    int32_t old_count = ecs_vector_count(sw->nodes);
    ecs_switch_set_count(sw, old_count + count);
}

void ecs_switch_set(
    ecs_switch_t *sw,
    int32_t element,
    uint64_t value)
{
    ecs_assert(sw != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(element < ecs_vector_count(sw->nodes), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(element < ecs_vector_count(sw->values), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(element >= 0, ECS_INVALID_PARAMETER, NULL);

    uint64_t *values = ecs_vector_first(sw->values, uint64_t);
    uint64_t cur_value = values[element];

    /* If the node is already assigned to the value, nothing to be done */
    if (cur_value == value) {
        return;
    }

    ecs_switch_node_t *nodes = ecs_vector_first(sw->nodes, ecs_switch_node_t);
    ecs_switch_node_t *node = &nodes[element];

    ecs_switch_header_t *cur_hdr = get_header(sw, cur_value);
    ecs_switch_header_t *dst_hdr = get_header(sw, value);

    /* If value is not 0, and dst_hdr is NULL, then this is not a valid value
     * for this switch */
    ecs_assert(dst_hdr != NULL || !value, ECS_INVALID_PARAMETER, NULL);

    if (cur_hdr) {
        remove_node(cur_hdr, nodes, node, element);
    }

    /* Now update the node itself by adding it as the first node of dst */
    node->prev = -1;
    values[element] = value;

    if (dst_hdr) {
        node->next = dst_hdr->element;

        /* Also update the dst header */
        int32_t first = dst_hdr->element;
        if (first != -1) {
            ecs_assert(first >= 0, ECS_INTERNAL_ERROR, NULL);
            ecs_switch_node_t *first_node = &nodes[first];
            first_node->prev = element;
        }

        dst_hdr->element = element;
        dst_hdr->count ++;        
    }
}

void ecs_switch_remove(
    ecs_switch_t *sw,
    int32_t element)
{
    ecs_assert(sw != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(element < ecs_vector_count(sw->nodes), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(element >= 0, ECS_INVALID_PARAMETER, NULL);

    uint64_t *values = ecs_vector_first(sw->values, uint64_t);
    uint64_t value = values[element];
    ecs_switch_node_t *nodes = ecs_vector_first(sw->nodes, ecs_switch_node_t);
    ecs_switch_node_t *node = &nodes[element];

    /* If node is currently assigned to a case, remove it from the list */
    if (value != 0) {
        ecs_switch_header_t *hdr = get_header(sw, value);
        ecs_assert(hdr != NULL, ECS_INTERNAL_ERROR, NULL);
        remove_node(hdr, nodes, node, element);
    }

    /* Remove element from arrays */
    ecs_vector_remove_index(sw->nodes, ecs_switch_node_t, element);
    ecs_vector_remove_index(sw->values, uint64_t, element);

    /* When the element was removed and the list was not empty, the last element
     * of the list got moved to the location of the removed node. Update the
     * linked list so that nodes that previously pointed to the last element
     * point to the moved node. 
     *
     * The 'node' variable is guaranteed to point to the moved element, if the
     * nodes list is not empty.
     *
     * If count is equal to the removed index, nothing needs to be done.
     */
    int32_t count = ecs_vector_count(sw->nodes);
    if (count != 0 && count != element) {
        int32_t prev = node->prev;
        if (prev != -1) {
            /* If the former last node was not the first node, update its
             * prev to point to its new index, which is the index of the removed
             * element. */
            ecs_assert(prev >= 0, ECS_INVALID_PARAMETER, NULL);
            nodes[prev].next = element;
        } else {
            /* If the former last node was the first node of its kind, find the
             * header for the value of the node. The header should have at
             * least one element. */
            ecs_switch_header_t *hdr = get_header(sw, values[element]);
            if (hdr && hdr->element != -1) {
                ecs_assert(hdr->element == ecs_vector_count(sw->nodes), 
                    ECS_INTERNAL_ERROR, NULL);
                hdr->element = element;
            }             
        }
    }
}

uint64_t ecs_switch_get(
    const ecs_switch_t *sw,
    int32_t element)
{
    ecs_assert(sw != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(element < ecs_vector_count(sw->nodes), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(element < ecs_vector_count(sw->values), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(element >= 0, ECS_INVALID_PARAMETER, NULL);

    uint64_t *values = ecs_vector_first(sw->values, uint64_t);
    return values[element];
}

ecs_vector_t* ecs_switch_values(
    const ecs_switch_t *sw)
{
    return sw->values;
}

int32_t ecs_switch_case_count(
    const ecs_switch_t *sw,
    uint64_t value)
{
    ecs_switch_header_t *hdr = get_header(sw, value);
    if (!hdr) {
        return 0;
    }

    return hdr->count;
}

void ecs_switch_swap(
    ecs_switch_t *sw,
    int32_t elem_1,
    int32_t elem_2)
{
    uint64_t v1 = ecs_switch_get(sw, elem_1);
    uint64_t v2 = ecs_switch_get(sw, elem_2);

    ecs_switch_set(sw, elem_2, v1);
    ecs_switch_set(sw, elem_1, v2);
}

int32_t ecs_switch_first(
    const ecs_switch_t *sw,
    uint64_t value)
{
    ecs_assert(sw != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert((uint32_t)value <= sw->max, ECS_INVALID_PARAMETER, NULL);
    ecs_assert((uint32_t)value >= sw->min, ECS_INVALID_PARAMETER, NULL);
    
    ecs_switch_header_t *hdr = get_header(sw, value);
    ecs_assert(hdr != NULL, ECS_INVALID_PARAMETER, NULL);

    return hdr->element;
}

int32_t ecs_switch_next(
    const ecs_switch_t *sw,
    int32_t element)
{
    ecs_assert(sw != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(element < ecs_vector_count(sw->nodes), ECS_INVALID_PARAMETER, NULL);
    ecs_assert(element >= 0, ECS_INVALID_PARAMETER, NULL);

    ecs_switch_node_t *nodes = ecs_vector_first(
        sw->nodes, ecs_switch_node_t);

    return nodes[element].next;
}

#ifndef _MSC_VER
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#endif

/*
-------------------------------------------------------------------------------
lookup3.c, by Bob Jenkins, May 2006, Public Domain.
  http://burtleburtle.net/bob/c/lookup3.c
-------------------------------------------------------------------------------
*/

#ifdef _MSC_VER
//FIXME
#else
#include <sys/param.h>  /* attempt to define endianness */
#endif
#ifdef linux
# include <endian.h>    /* attempt to define endianness */
#endif

/*
 * My best guess at if you are big-endian or little-endian.  This may
 * need adjustment.
 */
#if (defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && \
     __BYTE_ORDER == __LITTLE_ENDIAN) || \
    (defined(i386) || defined(__i386__) || defined(__i486__) || \
     defined(__i586__) || defined(__i686__) || defined(vax) || defined(MIPSEL))
# define HASH_LITTLE_ENDIAN 1
#elif (defined(__BYTE_ORDER) && defined(__BIG_ENDIAN) && \
       __BYTE_ORDER == __BIG_ENDIAN) || \
      (defined(sparc) || defined(POWERPC) || defined(mc68000) || defined(sel))
# define HASH_LITTLE_ENDIAN 0
#else
# define HASH_LITTLE_ENDIAN 0
#endif

#define rot(x,k) (((x)<<(k)) | ((x)>>(32-(k))))

/*
-------------------------------------------------------------------------------
mix -- mix 3 32-bit values reversibly.

This is reversible, so any information in (a,b,c) before mix() is
still in (a,b,c) after mix().

If four pairs of (a,b,c) inputs are run through mix(), or through
mix() in reverse, there are at least 32 bits of the output that
are sometimes the same for one pair and different for another pair.
This was tested for:
* pairs that differed by one bit, by two bits, in any combination
  of top bits of (a,b,c), or in any combination of bottom bits of
  (a,b,c).
* "differ" is defined as +, -, ^, or ~^.  For + and -, I transformed
  the output delta to a Gray code (a^(a>>1)) so a string of 1's (as
  is commonly produced by subtraction) look like a single 1-bit
  difference.
* the base values were pseudorandom, all zero but one bit set, or 
  all zero plus a counter that starts at zero.

Some k values for my "a-=c; a^=rot(c,k); c+=b;" arrangement that
satisfy this are
    4  6  8 16 19  4
    9 15  3 18 27 15
   14  9  3  7 17  3
Well, "9 15 3 18 27 15" didn't quite get 32 bits diffing
for "differ" defined as + with a one-bit base and a two-bit delta.  I
used http://burtleburtle.net/bob/hash/avalanche.html to choose 
the operations, constants, and arrangements of the variables.

This does not achieve avalanche.  There are input bits of (a,b,c)
that fail to affect some output bits of (a,b,c), especially of a.  The
most thoroughly mixed value is c, but it doesn't really even achieve
avalanche in c.

This allows some parallelism.  Read-after-writes are good at doubling
the number of bits affected, so the goal of mixing pulls in the opposite
direction as the goal of parallelism.  I did what I could.  Rotates
seem to cost as much as shifts on every machine I could lay my hands
on, and rotates are much kinder to the top and bottom bits, so I used
rotates.
-------------------------------------------------------------------------------
*/
#define mix(a,b,c) \
{ \
  a -= c;  a ^= rot(c, 4);  c += b; \
  b -= a;  b ^= rot(a, 6);  a += c; \
  c -= b;  c ^= rot(b, 8);  b += a; \
  a -= c;  a ^= rot(c,16);  c += b; \
  b -= a;  b ^= rot(a,19);  a += c; \
  c -= b;  c ^= rot(b, 4);  b += a; \
}

/*
-------------------------------------------------------------------------------
final -- final mixing of 3 32-bit values (a,b,c) into c

Pairs of (a,b,c) values differing in only a few bits will usually
produce values of c that look totally different.  This was tested for
* pairs that differed by one bit, by two bits, in any combination
  of top bits of (a,b,c), or in any combination of bottom bits of
  (a,b,c).
* "differ" is defined as +, -, ^, or ~^.  For + and -, I transformed
  the output delta to a Gray code (a^(a>>1)) so a string of 1's (as
  is commonly produced by subtraction) look like a single 1-bit
  difference.
* the base values were pseudorandom, all zero but one bit set, or 
  all zero plus a counter that starts at zero.

These constants passed:
 14 11 25 16 4 14 24
 12 14 25 16 4 14 24
and these came close:
  4  8 15 26 3 22 24
 10  8 15 26 3 22 24
 11  8 15 26 3 22 24
-------------------------------------------------------------------------------
*/
#define final(a,b,c) \
{ \
  c ^= b; c -= rot(b,14); \
  a ^= c; a -= rot(c,11); \
  b ^= a; b -= rot(a,25); \
  c ^= b; c -= rot(b,16); \
  a ^= c; a -= rot(c,4);  \
  b ^= a; b -= rot(a,14); \
  c ^= b; c -= rot(b,24); \
}


/*
 * hashlittle2: return 2 32-bit hash values
 *
 * This is identical to hashlittle(), except it returns two 32-bit hash
 * values instead of just one.  This is good enough for hash table
 * lookup with 2^^64 buckets, or if you want a second hash if you're not
 * happy with the first, or if you want a probably-unique 64-bit ID for
 * the key.  *pc is better mixed than *pb, so use *pc first.  If you want
 * a 64-bit value do something like "*pc + (((uint64_t)*pb)<<32)".
 */
static
void hashlittle2( 
  const void *key,       /* the key to hash */
  size_t      length,    /* length of the key */
  uint32_t   *pc,        /* IN: primary initval, OUT: primary hash */
  uint32_t   *pb)        /* IN: secondary initval, OUT: secondary hash */
{
  uint32_t a,b,c;                                          /* internal state */
  union { const void *ptr; size_t i; } u;     /* needed for Mac Powerbook G4 */

  /* Set up the internal state */
  a = b = c = 0xdeadbeef + ((uint32_t)length) + *pc;
  c += *pb;

  u.ptr = key;
  if (HASH_LITTLE_ENDIAN && ((u.i & 0x3) == 0)) {
    const uint32_t *k = (const uint32_t *)key;         /* read 32-bit chunks */
    const uint8_t  *k8;
    (void)k8;

    /*------ all but last block: aligned reads and affect 32 bits of (a,b,c) */
    while (length > 12)
    {
      a += k[0];
      b += k[1];
      c += k[2];
      mix(a,b,c);
      length -= 12;
      k += 3;
    }

    /*----------------------------- handle the last (probably partial) block */
    /* 
     * "k[2]&0xffffff" actually reads beyond the end of the string, but
     * then masks off the part it's not allowed to read.  Because the
     * string is aligned, the masked-off tail is in the same word as the
     * rest of the string.  Every machine with memory protection I've seen
     * does it on word boundaries, so is OK with this.  But VALGRIND will
     * still catch it and complain.  The masking trick does make the hash
     * noticably faster for short strings (like English words).
     */
#ifndef VALGRIND

    switch(length)
    {
    case 12: c+=k[2]; b+=k[1]; a+=k[0]; break;
    case 11: c+=k[2]&0xffffff; b+=k[1]; a+=k[0]; break;
    case 10: c+=k[2]&0xffff; b+=k[1]; a+=k[0]; break;
    case 9 : c+=k[2]&0xff; b+=k[1]; a+=k[0]; break;
    case 8 : b+=k[1]; a+=k[0]; break;
    case 7 : b+=k[1]&0xffffff; a+=k[0]; break;
    case 6 : b+=k[1]&0xffff; a+=k[0]; break;
    case 5 : b+=k[1]&0xff; a+=k[0]; break;
    case 4 : a+=k[0]; break;
    case 3 : a+=k[0]&0xffffff; break;
    case 2 : a+=k[0]&0xffff; break;
    case 1 : a+=k[0]&0xff; break;
    case 0 : *pc=c; *pb=b; return;  /* zero length strings require no mixing */
    }

#else /* make valgrind happy */

    k8 = (const uint8_t *)k;
    switch(length)
    {
    case 12: c+=k[2]; b+=k[1]; a+=k[0]; break;
    case 11: c+=((uint32_t)k8[10])<<16;  /* fall through */
    case 10: c+=((uint32_t)k8[9])<<8;    /* fall through */
    case 9 : c+=k8[8];                   /* fall through */
    case 8 : b+=k[1]; a+=k[0]; break;
    case 7 : b+=((uint32_t)k8[6])<<16;   /* fall through */
    case 6 : b+=((uint32_t)k8[5])<<8;    /* fall through */
    case 5 : b+=k8[4];                   /* fall through */
    case 4 : a+=k[0]; break;
    case 3 : a+=((uint32_t)k8[2])<<16;   /* fall through */
    case 2 : a+=((uint32_t)k8[1])<<8;    /* fall through */
    case 1 : a+=k8[0]; break;
    case 0 : *pc=c; *pb=b; return;  /* zero length strings require no mixing */
    }

#endif /* !valgrind */

  } else if (HASH_LITTLE_ENDIAN && ((u.i & 0x1) == 0)) {
    const uint16_t *k = (const uint16_t *)key;         /* read 16-bit chunks */
    const uint8_t  *k8;

    /*--------------- all but last block: aligned reads and different mixing */
    while (length > 12)
    {
      a += k[0] + (((uint32_t)k[1])<<16);
      b += k[2] + (((uint32_t)k[3])<<16);
      c += k[4] + (((uint32_t)k[5])<<16);
      mix(a,b,c);
      length -= 12;
      k += 6;
    }

    /*----------------------------- handle the last (probably partial) block */
    k8 = (const uint8_t *)k;
    switch(length)
    {
    case 12: c+=k[4]+(((uint32_t)k[5])<<16);
             b+=k[2]+(((uint32_t)k[3])<<16);
             a+=k[0]+(((uint32_t)k[1])<<16);
             break;
    case 11: c+=((uint32_t)k8[10])<<16;     /* fall through */
    case 10: c+=k[4];
             b+=k[2]+(((uint32_t)k[3])<<16);
             a+=k[0]+(((uint32_t)k[1])<<16);
             break;
    case 9 : c+=k8[8];                      /* fall through */
    case 8 : b+=k[2]+(((uint32_t)k[3])<<16);
             a+=k[0]+(((uint32_t)k[1])<<16);
             break;
    case 7 : b+=((uint32_t)k8[6])<<16;      /* fall through */
    case 6 : b+=k[2];
             a+=k[0]+(((uint32_t)k[1])<<16);
             break;
    case 5 : b+=k8[4];                      /* fall through */
    case 4 : a+=k[0]+(((uint32_t)k[1])<<16);
             break;
    case 3 : a+=((uint32_t)k8[2])<<16;      /* fall through */
    case 2 : a+=k[0];
             break;
    case 1 : a+=k8[0];
             break;
    case 0 : *pc=c; *pb=b; return;  /* zero length strings require no mixing */
    }

  } else {                        /* need to read the key one byte at a time */
    const uint8_t *k = (const uint8_t *)key;

    /*--------------- all but the last block: affect some 32 bits of (a,b,c) */
    while (length > 12)
    {
      a += k[0];
      a += ((uint32_t)k[1])<<8;
      a += ((uint32_t)k[2])<<16;
      a += ((uint32_t)k[3])<<24;
      b += k[4];
      b += ((uint32_t)k[5])<<8;
      b += ((uint32_t)k[6])<<16;
      b += ((uint32_t)k[7])<<24;
      c += k[8];
      c += ((uint32_t)k[9])<<8;
      c += ((uint32_t)k[10])<<16;
      c += ((uint32_t)k[11])<<24;
      mix(a,b,c);
      length -= 12;
      k += 12;
    }

    /*-------------------------------- last block: affect all 32 bits of (c) */
    switch(length)                   /* all the case statements fall through */
    {
    case 12: c+=((uint32_t)k[11])<<24;
    case 11: c+=((uint32_t)k[10])<<16;
    case 10: c+=((uint32_t)k[9])<<8;
    case 9 : c+=k[8];
    case 8 : b+=((uint32_t)k[7])<<24;
    case 7 : b+=((uint32_t)k[6])<<16;
    case 6 : b+=((uint32_t)k[5])<<8;
    case 5 : b+=k[4];
    case 4 : a+=((uint32_t)k[3])<<24;
    case 3 : a+=((uint32_t)k[2])<<16;
    case 2 : a+=((uint32_t)k[1])<<8;
    case 1 : a+=k[0];
             break;
    case 0 : *pc=c; *pb=b; return;  /* zero length strings require no mixing */
    }
  }

  final(a,b,c);
  *pc=c; *pb=b;
}

void ecs_hash(
    const void *data,
    ecs_size_t length,
    uint64_t *result)
{
    uint32_t h_1 = 0;
    uint32_t h_2 = 0;

    hashlittle2(
        data,
        ecs_to_size_t(length),
        &h_1,
        &h_2);

    *result = h_1 | ((uint64_t)h_2 << 32);
}


static
bool term_id_is_set(
    const ecs_term_id_t *id)
{
    return id->entity != 0 || id->name != NULL;
}

static
int resolve_identifier(
    const ecs_world_t *world,
    const char *name,
    const char *expr,
    ecs_term_id_t *identifier)
{
    if (!identifier->name) {
        return 0;
    }

    if (identifier->var_kind == EcsVarDefault) {
        if (ecs_identifier_is_var(identifier->name)) {
            identifier->var_kind = EcsVarIsVariable;
        }
    }

    if (identifier->var_kind != EcsVarIsVariable) {
        if (ecs_identifier_is_0(identifier->name)) {
            identifier->entity = 0;
        } else {
            ecs_entity_t e = ecs_lookup_fullpath(world, identifier->name);
            if (!e) {
                ecs_parser_error(name, expr, 0,
                    "unresolved identifier '%s'", identifier->name);
                return -1;
            }

            /* Use OR, as entity may have already been populated with role */
            identifier->entity = e;
        }
    }

    return 0;
}

bool ecs_identifier_is_0(
    const char *id)
{
    return id[0] == '0' && !id[1];
}

bool ecs_identifier_is_var(
    const char *id)
{
    if (id[0] == '_') {
        return true;
    }

    if (isdigit(id[0])) {
        return false;
    }

    const char *ptr;
    char ch;
    for (ptr = id; (ch = *ptr); ptr ++) {
        if (!isupper(ch) && ch != '_' && !isdigit(ch)) {
            return false;
        }
    }

    return true;
}

static
int term_resolve_ids(
    const ecs_world_t *world,
    const char *name,
    const char *expr,
    ecs_term_t *term)
{
    if (resolve_identifier(world, name, expr, &term->pred)) {
        return -1;
    }
    if (resolve_identifier(world, name, expr, &term->args[0])) {
        return -1;
    }
    if (resolve_identifier(world, name, expr, &term->args[1])) {
        return -1;
    }

    if (term->args[1].entity) {
        term->id = ecs_pair(term->pred.entity, term->args[1].entity);
    } else {
        term->id = term->pred.entity;
    }

    term->id |= term->role;

    return 0;
}

bool ecs_term_is_set(
    const ecs_term_t *term)
{
    return term->id != 0 || term_id_is_set(&term->pred);
}

bool ecs_term_is_trivial(
    ecs_term_t *term)
{
    if (term->inout != EcsInOutDefault) {
        return false;
    }

    if (term->args[0].entity != EcsThis) {
        return false;
    }

    if (term->args[0].set != EcsDefaultSet) {
        return false;
    }

    if (term->oper != EcsAnd && term->oper != EcsAndFrom) {
        return false;
    }

    if (term->name != NULL) {
        return false;
    }

    return true;
}

int ecs_term_finalize(
    const ecs_world_t *world,
    const char *name,
    const char *expr,
    ecs_term_t *term)
{
    /* If id is set, derive predicate and object */
    if (term->id) {
        if (term->args[0].entity && term->args[0].entity != EcsThis) {
            ecs_parser_error(name, expr, 0, 
                "cannot combine id with subject that is not This");
            return -1;
        }

        if (ECS_HAS_ROLE(term->id, PAIR)) {
            term->pred.entity = ECS_PAIR_RELATION(term->id);
            term->args[1].entity = ECS_PAIR_OBJECT(term->id);
        } else {
            term->pred.entity = term->id & ECS_COMPONENT_MASK;
        }

        term->args[0].entity = EcsThis;
        term->role = term->id & ECS_ROLE_MASK;
    } else {
        if (term_resolve_ids(world, name, expr, term)) {
            /* One or more identifiers could not be resolved */
            return -1;
        }
    }

    return 0;
}

void ecs_term_copy(
    ecs_term_t *dst,
    const ecs_term_t *src)
{
    *dst = *src;
    dst->name = ecs_os_strdup(src->name);
    dst->pred.name = ecs_os_strdup(src->pred.name);
    dst->args[0].name = ecs_os_strdup(src->args[0].name);
    dst->args[1].name = ecs_os_strdup(src->args[1].name);
}

void ecs_term_fini(
    ecs_term_t *term)
{
    ecs_os_free(term->pred.name);
    ecs_os_free(term->args[0].name);
    ecs_os_free(term->args[1].name);
    ecs_os_free(term->name);
}

int ecs_filter_init(
    const ecs_world_t *world,
    ecs_filter_t *filter_out,
    const ecs_filter_desc_t *desc)    
{
    int i, term_count = 0;
    ecs_term_t *terms = desc->terms_buffer;
    const char *name = desc->name;
    const char *expr = desc->expr;

    ecs_filter_t f = {
        /* Temporarily set the fields to the values provided in desc, until the
         * filter has been validated. */
        .name = (char*)name,
        .expr = (char*)expr
    };

    if (expr) {
#ifdef FLECS_PARSER
        /* Cannot set expression and terms at the same time */
        ecs_assert(terms == NULL, ECS_INVALID_PARAMETER, NULL);
        
        /* Parse expression into array of terms */
        int32_t buffer_count = 0;
        const char *ptr = desc->expr;
        ecs_term_t term = {0};
        while (ptr[0] && (ptr = ecs_parse_term(world, name, expr, ptr, &term))){
            if (!ecs_term_is_set(&term)) {
                break;
            }
            
            if (term_count == buffer_count) {
                buffer_count = buffer_count ? buffer_count * 2 : 8;
                terms = ecs_os_realloc(terms, 
                    buffer_count * ECS_SIZEOF(ecs_term_t));
            }

            terms[term_count] = term;
            term_count ++;
        }

        f.terms = terms;
        f.term_count = term_count;

        if (!ptr) {
            goto error;
        }
#else
        ecs_abort(ECS_UNSUPPORTED, "parser addon is not available");
#endif
    } else {
        if (terms) {
            terms = desc->terms_buffer;
            term_count = desc->terms_buffer_count;
        } else {
            terms = (ecs_term_t*)desc->terms;
            for (i = 0; i < ECS_FILTER_DESC_TERM_ARRAY_MAX; i ++) {
                if (!ecs_term_is_set(&terms[i])) {
                    break;
                }

                term_count ++;
            }
        }

        /* Temporarily set array from desc to filter, until the filter has been
         * validated. */
        f.terms = terms;
        f.term_count = term_count;
    }

    /* Ensure all fields are consistent and properly filled out */
    if (ecs_filter_finalize(world, &f)) {
        goto error;
    }

    /* Copy term resources. If an expression was provided, the resources in the
     * terms are already owned by the filter. */
    if (!f.expr) {
        if (term_count) {
            f.terms = ecs_os_malloc(term_count * ECS_SIZEOF(ecs_term_t));
            for (i = 0; i < term_count; i ++) {
                ecs_term_copy(&f.terms[i], &terms[i]);
            }
        } else {
            f.terms = NULL;
        }
    }

    f.name = ecs_os_strdup(desc->name);
    f.expr = ecs_os_strdup(desc->expr);

    *filter_out = f;

    return 0;
error:
    /* NULL members that point to non-owned resources */
    if (!f.expr) {
        f.terms = NULL;
    }

    f.name = NULL;
    f.expr = NULL;

    ecs_filter_fini(&f);

    return -1;
}

int ecs_filter_finalize(
    const ecs_world_t *world,
    ecs_filter_t *f)
{
    int32_t i, term_count = f->term_count, index = 0;
    ecs_term_t *terms = f->terms;
    ecs_oper_kind_t prev_oper = 0;

    for (i = 0; i < term_count; i ++) {
        ecs_term_t *term = &terms[i];

        if (ecs_term_finalize(world, f->name, f->expr, term)) {
            return -1;
        }

        term->index = index;

        /* Fold OR terms */
        if (prev_oper != EcsOr || term->oper != EcsOr) {
            index ++;
        }

        prev_oper = term->oper;
    }

    f->term_count_actual = index;

    return 0;
}

static
void filter_str_add_id(
    const ecs_world_t *world,
    ecs_strbuf_t *buf,
    ecs_term_id_t *id)
{
    if (id->name) {
        ecs_strbuf_appendstr(buf, id->name);
    } else if (id->entity) {
        char *path = ecs_get_fullpath(world, id->entity);
        ecs_strbuf_appendstr(buf, path);
        ecs_os_free(path);
    } else {
        ecs_strbuf_appendstr(buf, "0");
    }
}

char* ecs_filter_str(
    const ecs_world_t *world,
    ecs_filter_t *filter)
{
    ecs_strbuf_t buf = ECS_STRBUF_INIT;

    ecs_term_t *terms = filter->terms;
    int32_t i, count = filter->term_count;
    int32_t or_count = 0;

    for (i = 0; i < count; i ++) {
        ecs_term_t *term = &terms[i];

        if (i) {
            if (terms[i - 1].oper == EcsOr && term->oper == EcsOr) {
                ecs_strbuf_appendstr(&buf, " || ");
            } else {
                ecs_strbuf_appendstr(&buf, ", ");
            }
        }

        if (or_count < 1) {
            if (term->inout == EcsIn) {
                ecs_strbuf_appendstr(&buf, "[in] ");
            } else if (term->inout == EcsInOut) {
                ecs_strbuf_appendstr(&buf, "[inout] ");
            } else if (term->inout == EcsInOut) {
                ecs_strbuf_appendstr(&buf, "[out] ");
            }
        }

        if (term->role) {
            ecs_strbuf_appendstr(&buf, ecs_role_str(term->role));
            ecs_strbuf_appendstr(&buf, " ");
        }

        if (term->oper == EcsOr) {
            or_count ++;
        } else {
            or_count = 0;
        }

        if (term->oper == EcsNot) {
            ecs_strbuf_appendstr(&buf, "!");
        } else if (term->oper == EcsOptional) {
            ecs_strbuf_appendstr(&buf, "?");
        }

        if (term->args[0].entity == EcsThis && term_id_is_set(&term->args[1])) {
            ecs_strbuf_appendstr(&buf, "(");
        }

        if (!term_id_is_set(&term->args[1]) && 
            (term->pred.entity != term->args[0].entity)) 
        {
            filter_str_add_id(world, &buf, &term->pred);

            if (!term_id_is_set(&term->args[0])) {
                ecs_strbuf_appendstr(&buf, "()");
            } else if (term->args[0].entity != EcsThis) {
                ecs_strbuf_appendstr(&buf, "(");
                filter_str_add_id(world, &buf, &term->args[0]);
            }

            if (term_id_is_set(&term->args[1])) {
                ecs_strbuf_appendstr(&buf, ", ");
                filter_str_add_id(world, &buf, &term->args[1]);
                ecs_strbuf_appendstr(&buf, ")");
            }
        } else {
            ecs_strbuf_appendstr(&buf, "$");
            filter_str_add_id(world, &buf, &term->pred);
        }
    }

    return ecs_strbuf_get(&buf);
}

void ecs_filter_fini(
    ecs_filter_t *filter) 
{
    if (filter->terms) {
        int i, count = filter->term_count;
        for (i = 0; i < count; i ++) {
            ecs_term_fini(&filter->terms[i]);
        }

        ecs_os_free(filter->terms);
    }

    ecs_os_free(filter->name);
    ecs_os_free(filter->expr);
}

bool ecs_filter_match_entity(
    const ecs_world_t *world,
    const ecs_filter_t *filter,
    ecs_entity_t e)
{
    ecs_assert(e == 0, ECS_UNSUPPORTED, NULL);
    (void)e;

    ecs_term_t *terms = filter->terms;
    int32_t i, count = filter->term_count;

    for (i = 0; i < count; i ++) {
        ecs_term_t *term = &terms[i];
        ecs_term_id_t *subj = &term->args[0];
        ecs_oper_kind_t oper = term->oper;

        if (subj->entity != EcsThis && subj->set & EcsSelf) {
            ecs_type_t type = ecs_get_type(world, subj->entity);
            if (ecs_type_has_id(world, type, term->id)) {
                if (oper == EcsNot) {
                    return false;
                }
            } else {
                if (oper != EcsNot) {
                    return false;
                }
            }
        }        
    }

    return true;    
}

ecs_iter_t ecs_filter_iter(
    ecs_world_t *world,
    const ecs_filter_t *filter)
{
    ecs_filter_iter_t iter = {
        .filter = filter ? *filter : (ecs_filter_t){0},
        .tables = world->store.tables,
        .index = 0
    };

    return (ecs_iter_t){
        .world = world,
        .iter.filter = iter
    };
}

bool ecs_filter_next(
    ecs_iter_t *it)
{
    ecs_filter_iter_t *iter = &it->iter.filter;
    ecs_sparse_t *tables = iter->tables;
    int32_t count = ecs_sparse_count(tables);
    int32_t i;

    for (i = iter->index; i < count; i ++) {
        ecs_table_t *table = ecs_sparse_get(tables, ecs_table_t, i);
        ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);
        
        ecs_data_t *data = ecs_table_get_data(table);

        if (!data) {
            continue;
        }

        if (!ecs_table_match_filter(it->world, table, &iter->filter)) {
            continue;
        }

        iter->table.table = table;
        it->table = &iter->table;
        it->table_columns = data->columns;
        it->count = ecs_table_count(table);
        it->entities = ecs_vector_first(data->entities, ecs_entity_t);
        iter->index = i + 1;

        return true;
    }

    return false;
}


static
void ensure(
    ecs_bitset_t *bs,
    ecs_size_t size)
{
    if (!bs->size) {
        int32_t new_size = ((size - 1) / 64 + 1) * ECS_SIZEOF(uint64_t);
        bs->size = ((size - 1) / 64 + 1) * 64;
        bs->data = ecs_os_calloc(new_size);
    } else if (size > bs->size) {
        int32_t prev_size = ((bs->size - 1) / 64 + 1) * ECS_SIZEOF(uint64_t);
        bs->size = ((size - 1) / 64 + 1) * 64;
        int32_t new_size = ((size - 1) / 64 + 1) * ECS_SIZEOF(uint64_t);
        bs->data = ecs_os_realloc(bs->data, new_size);
        ecs_os_memset(ECS_OFFSET(bs->data, prev_size), 0, new_size - prev_size);
    }
}

void ecs_bitset_init(
    ecs_bitset_t* bs)
{
    bs->size = 0;
    bs->count = 0;
    bs->data = NULL;
}

void ecs_bitset_ensure(
    ecs_bitset_t *bs,
    int32_t count)
{
    if (count > bs->count) {
        bs->count = count;
        ensure(bs, count);
    }
}

void ecs_bitset_deinit(
    ecs_bitset_t *bs)
{
    ecs_os_free(bs->data);
}

void ecs_bitset_addn(
    ecs_bitset_t *bs,
    int32_t count)
{
    int32_t elem = bs->count += count;
    ensure(bs, elem);
}

void ecs_bitset_set(
    ecs_bitset_t *bs,
    int32_t elem,
    bool value)
{
    ecs_assert(elem < bs->count, ECS_INVALID_PARAMETER, NULL);
    int32_t hi = elem >> 6;
    int32_t lo = elem & 0x3F;
    uint64_t v = bs->data[hi];
    bs->data[hi] = (v & ~((uint64_t)1 << lo)) | ((uint64_t)value << lo);
}

bool ecs_bitset_get(
    const ecs_bitset_t *bs,
    int32_t elem)
{
    ecs_assert(elem < bs->count, ECS_INVALID_PARAMETER, NULL);
    return !!(bs->data[elem >> 6] & ((uint64_t)1 << ((uint64_t)elem & 0x3F)));
}

int32_t ecs_bitset_count(
    const ecs_bitset_t *bs)
{
    return bs->count;
}

void ecs_bitset_remove(
    ecs_bitset_t *bs,
    int32_t elem)
{
    ecs_assert(elem < bs->count, ECS_INVALID_PARAMETER, NULL);
    int32_t last = bs->count - 1;
    bool last_value = ecs_bitset_get(bs, last);
    ecs_bitset_set(bs, elem, last_value);
    bs->count --;
}

void ecs_bitset_swap(
    ecs_bitset_t *bs,
    int32_t elem_a,
    int32_t elem_b)
{
    ecs_assert(elem_a < bs->count, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(elem_b < bs->count, ECS_INVALID_PARAMETER, NULL);

    bool a = ecs_bitset_get(bs, elem_a);
    bool b = ecs_bitset_get(bs, elem_b);
    ecs_bitset_set(bs, elem_a, b);
    ecs_bitset_set(bs, elem_b, a);
}

/* Add an extra element to the buffer */
static
void ecs_strbuf_grow(
    ecs_strbuf_t *b)
{
    /* Allocate new element */
    ecs_strbuf_element_embedded *e = ecs_os_malloc(sizeof(ecs_strbuf_element_embedded));
    b->size += b->current->pos;
    b->current->next = (ecs_strbuf_element*)e;
    b->current = (ecs_strbuf_element*)e;
    b->elementCount ++;
    e->super.buffer_embedded = true;
    e->super.buf = e->buf;
    e->super.pos = 0;
    e->super.next = NULL;
}

/* Add an extra dynamic element */
static
void ecs_strbuf_grow_str(
    ecs_strbuf_t *b,
    char *str,
    char *alloc_str,
    int32_t size)
{
    /* Allocate new element */
    ecs_strbuf_element_str *e = ecs_os_malloc(sizeof(ecs_strbuf_element_str));
    b->size += b->current->pos;
    b->current->next = (ecs_strbuf_element*)e;
    b->current = (ecs_strbuf_element*)e;
    b->elementCount ++;
    e->super.buffer_embedded = false;
    e->super.pos = size ? size : (int32_t)ecs_os_strlen(str);
    e->super.next = NULL;
    e->super.buf = str;
    e->alloc_str = alloc_str;
}

static
char* ecs_strbuf_ptr(
    ecs_strbuf_t *b)
{
    if (b->buf) {
        return &b->buf[b->current->pos];
    } else {
        return &b->current->buf[b->current->pos];
    }
}

/* Compute the amount of space left in the current element */
static
int32_t ecs_strbuf_memLeftInCurrentElement(
    ecs_strbuf_t *b)
{
    if (b->current->buffer_embedded) {
        return ECS_STRBUF_ELEMENT_SIZE - b->current->pos;
    } else {
        return 0;
    }
}

/* Compute the amount of space left */
static
int32_t ecs_strbuf_memLeft(
    ecs_strbuf_t *b)
{
    if (b->max) {
        return b->max - b->size - b->current->pos;
    } else {
        return INT_MAX;
    }
}

static
void ecs_strbuf_init(
    ecs_strbuf_t *b)
{
    /* Initialize buffer structure only once */
    if (!b->elementCount) {
        b->size = 0;
        b->firstElement.super.next = NULL;
        b->firstElement.super.pos = 0;
        b->firstElement.super.buffer_embedded = true;
        b->firstElement.super.buf = b->firstElement.buf;
        b->elementCount ++;
        b->current = (ecs_strbuf_element*)&b->firstElement;
    }
}

/* Quick custom function to copy a maxium number of characters and
 * simultaneously determine length of source string. */
static
int32_t fast_strncpy(
    char * dst,
    const char * src,
    int n_cpy,
    int n)
{
    ecs_assert(n_cpy >= 0, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(n >= 0, ECS_INTERNAL_ERROR, NULL);

    const char *ptr, *orig = src;
    char ch;

    for (ptr = src; (ptr - orig < n) && (ch = *ptr); ptr ++) {
        if (ptr - orig < n_cpy) {
            *dst = ch;
            dst ++;
        }
    }

    ecs_assert(ptr - orig < INT32_MAX, ECS_INTERNAL_ERROR, NULL);

    return (int32_t)(ptr - orig);
}

/* Append a format string to a buffer */
static
bool ecs_strbuf_vappend_intern(
    ecs_strbuf_t *b,
    const char* str,
    va_list args)
{
    bool result = true;
    va_list arg_cpy;

    if (!str) {
        return result;
    }

    ecs_strbuf_init(b);

    int32_t memLeftInElement = ecs_strbuf_memLeftInCurrentElement(b);
    int32_t memLeft = ecs_strbuf_memLeft(b);

    if (!memLeft) {
        return false;
    }

    /* Compute the memory required to add the string to the buffer. If user
     * provided buffer, use space left in buffer, otherwise use space left in
     * current element. */
    int32_t max_copy = b->buf ? memLeft : memLeftInElement;
    int32_t memRequired;

    va_copy(arg_cpy, args);
    memRequired = vsnprintf(
        ecs_strbuf_ptr(b), (size_t)(max_copy + 1), str, args);

    ecs_assert(memRequired != -1, ECS_INTERNAL_ERROR, NULL);

    if (memRequired <= memLeftInElement) {
        /* Element was large enough to fit string */
        b->current->pos += memRequired;
    } else if ((memRequired - memLeftInElement) < memLeft) {
        /* If string is a format string, a new buffer of size memRequired is
         * needed to re-evaluate the format string and only use the part that
         * wasn't already copied to the previous element */
        if (memRequired <= ECS_STRBUF_ELEMENT_SIZE) {
            /* Resulting string fits in standard-size buffer. Note that the
             * entire string needs to fit, not just the remainder, as the
             * format string cannot be partially evaluated */
            ecs_strbuf_grow(b);

            /* Copy entire string to new buffer */
            ecs_os_vsprintf(ecs_strbuf_ptr(b), str, arg_cpy);

            /* Ignore the part of the string that was copied into the
             * previous buffer. The string copied into the new buffer could
             * be memmoved so that only the remainder is left, but that is
             * most likely more expensive than just keeping the entire
             * string. */

            /* Update position in buffer */
            b->current->pos += memRequired;
        } else {
            /* Resulting string does not fit in standard-size buffer.
             * Allocate a new buffer that can hold the entire string. */
            char *dst = ecs_os_malloc(memRequired + 1);
            ecs_os_vsprintf(dst, str, arg_cpy);
            ecs_strbuf_grow_str(b, dst, dst, memRequired);
        }
    } else {
        /* Buffer max has been reached */
        result = false;
    }

    va_end(arg_cpy);

    return result;
}

static
bool ecs_strbuf_append_intern(
    ecs_strbuf_t *b,
    const char* str,
    int n)
{
    bool result = true;

    if (!str) {
        return result;
    }

    ecs_strbuf_init(b);

    int32_t memLeftInElement = ecs_strbuf_memLeftInCurrentElement(b);
    int32_t memLeft = ecs_strbuf_memLeft(b);

    if (memLeft <= 0) {
        return false;
    }

    /* Compute the memory required to add the string to the buffer. If user
     * provided buffer, use space left in buffer, otherwise use space left in
     * current element. */
    int32_t max_copy = b->buf ? memLeft : memLeftInElement;
    int32_t memRequired;

    if (n < 0) n = INT_MAX;

    memRequired = fast_strncpy(ecs_strbuf_ptr(b), str, max_copy, n);

    if (memRequired <= memLeftInElement) {
        /* Element was large enough to fit string */
        b->current->pos += memRequired;
    } else if ((memRequired - memLeftInElement) < memLeft) {
        /* Element was not large enough, but buffer still has space */
        b->current->pos += memLeftInElement;
        memRequired -= memLeftInElement;

        /* Current element was too small, copy remainder into new element */
        if (memRequired < ECS_STRBUF_ELEMENT_SIZE) {
            /* A standard-size buffer is large enough for the new string */
            ecs_strbuf_grow(b);

            /* Copy the remainder to the new buffer */
            if (n) {
                /* If a max number of characters to write is set, only a
                    * subset of the string should be copied to the buffer */
                ecs_os_strncpy(
                    ecs_strbuf_ptr(b),
                    str + memLeftInElement,
                    (size_t)memRequired);
            } else {
                ecs_os_strcpy(ecs_strbuf_ptr(b), str + memLeftInElement);
            }

            /* Update to number of characters copied to new buffer */
            b->current->pos += memRequired;
        } else {
            char *remainder = ecs_os_strdup(str + memLeftInElement);
            ecs_strbuf_grow_str(b, remainder, remainder, memRequired);
        }
    } else {
        /* Buffer max has been reached */
        result = false;
    }

    return result;
}

bool ecs_strbuf_vappend(
    ecs_strbuf_t *b,
    const char* fmt,
    va_list args)
{
    bool result = ecs_strbuf_vappend_intern(
        b, fmt, args
    );

    return result;
}

bool ecs_strbuf_append(
    ecs_strbuf_t *b,
    const char* fmt,
    ...)
{
    va_list args;
    va_start(args, fmt);
    bool result = ecs_strbuf_vappend_intern(
        b, fmt, args
    );
    va_end(args);

    return result;
}

bool ecs_strbuf_appendstrn(
    ecs_strbuf_t *b,
    const char* str,
    int32_t len)
{
    return ecs_strbuf_append_intern(
        b, str, len
    );
}

bool ecs_strbuf_appendstr_zerocpy(
    ecs_strbuf_t *b,
    char* str)
{
    ecs_strbuf_init(b);
    ecs_strbuf_grow_str(b, str, str, 0);
    return true;
}

bool ecs_strbuf_appendstr_zerocpy_const(
    ecs_strbuf_t *b,
    const char* str)
{
    /* Removes const modifier, but logic prevents changing / delete string */
    ecs_strbuf_init(b);
    ecs_strbuf_grow_str(b, (char*)str, NULL, 0);
    return true;
}

bool ecs_strbuf_appendstr(
    ecs_strbuf_t *b,
    const char* str)
{
    return ecs_strbuf_append_intern(
        b, str, -1
    );
}

bool ecs_strbuf_mergebuff(
    ecs_strbuf_t *dst_buffer,
    ecs_strbuf_t *src_buffer)
{
    if (src_buffer->elementCount) {
        if (src_buffer->buf) {
            return ecs_strbuf_appendstr(dst_buffer, src_buffer->buf);
        } else {
            ecs_strbuf_element *e = (ecs_strbuf_element*)&src_buffer->firstElement;

            /* Copy first element as it is inlined in the src buffer */
            ecs_strbuf_appendstrn(dst_buffer, e->buf, e->pos);

            while ((e = e->next)) {
                dst_buffer->current->next = ecs_os_malloc(sizeof(ecs_strbuf_element));
                *dst_buffer->current->next = *e;
            }
        }

        *src_buffer = ECS_STRBUF_INIT;
    }

    return true;
}

char* ecs_strbuf_get(ecs_strbuf_t *b) {
    char* result = NULL;

    if (b->elementCount) {
        if (b->buf) {
            b->buf[b->current->pos] = '\0';
            result = ecs_os_strdup(b->buf);
        } else {
            void *next = NULL;
            int32_t len = b->size + b->current->pos + 1;

            ecs_strbuf_element *e = (ecs_strbuf_element*)&b->firstElement;

            result = ecs_os_malloc(len);
            char* ptr = result;

            do {
                ecs_os_memcpy(ptr, e->buf, e->pos);
                ptr += e->pos;
                next = e->next;
                if (e != &b->firstElement.super) {
                    if (!e->buffer_embedded) {
                        ecs_os_free(((ecs_strbuf_element_str*)e)->alloc_str);
                    }
                    ecs_os_free(e);
                }
            } while ((e = next));

            result[len - 1] = '\0';
        }
    } else {
        result = NULL;
    }

    b->elementCount = 0;

    return result;
}

void ecs_strbuf_reset(ecs_strbuf_t *b) {
    if (b->elementCount && !b->buf) {
        void *next = NULL;
        ecs_strbuf_element *e = (ecs_strbuf_element*)&b->firstElement;
        do {
            next = e->next;
            if (e != (ecs_strbuf_element*)&b->firstElement) {
                ecs_os_free(e);
            }
        } while ((e = next));
    }

    *b = ECS_STRBUF_INIT;
}

void ecs_strbuf_list_push(
    ecs_strbuf_t *buffer,
    const char *list_open,
    const char *separator)
{
    buffer->list_sp ++;
    buffer->list_stack[buffer->list_sp].count = 0;
    buffer->list_stack[buffer->list_sp].separator = separator;

    if (list_open) {
        ecs_strbuf_appendstr(buffer, list_open);
    }
}

void ecs_strbuf_list_pop(
    ecs_strbuf_t *buffer,
    const char *list_close)
{
    buffer->list_sp --;
    
    if (list_close) {
        ecs_strbuf_appendstr(buffer, list_close);
    }
}

void ecs_strbuf_list_next(
    ecs_strbuf_t *buffer)
{
    int32_t list_sp = buffer->list_sp;
    if (buffer->list_stack[list_sp].count != 0) {
        ecs_strbuf_appendstr(buffer, buffer->list_stack[list_sp].separator);
    }
    buffer->list_stack[list_sp].count ++;
}

bool ecs_strbuf_list_append(
    ecs_strbuf_t *buffer,
    const char *fmt,
    ...)
{
    ecs_strbuf_list_next(buffer);

    va_list args;
    va_start(args, fmt);
    bool result = ecs_strbuf_vappend_intern(
        buffer, fmt, args
    );
    va_end(args);

    return result;
}

bool ecs_strbuf_list_appendstr(
    ecs_strbuf_t *buffer,
    const char *str)
{
    ecs_strbuf_list_next(buffer);
    return ecs_strbuf_appendstr(buffer, str);
}

ecs_entity_t ecs_find_entity_in_prefabs(
    const ecs_world_t *world,
    ecs_entity_t entity,
    ecs_type_t type,
    ecs_entity_t component,
    ecs_entity_t previous)
{
    int32_t i, count = ecs_vector_count(type);
    ecs_entity_t *array = ecs_vector_first(type, ecs_entity_t);

    /* Walk from back to front, as prefabs are always located
     * at the end of the type. */
    for (i = count - 1; i >= 0; i --) {
        ecs_entity_t e = array[i];

        if (ECS_HAS_RELATION(e, EcsIsA)) {
            ecs_entity_t prefab = ecs_pair_object(world, e);
            ecs_type_t prefab_type = ecs_get_type(world, prefab);

            if (prefab == previous) {
                continue;
            }

            if (ecs_type_owns_id(
                world, prefab_type, component, true)) 
            {
                return prefab;
            } else {
                prefab = ecs_find_entity_in_prefabs(
                    world, prefab, prefab_type, component, entity);
                if (prefab) {
                    return prefab;
                }
            }
        }
    }

    return 0;
}

/* -- Private functions -- */

/* O(n) algorithm to check whether type 1 is equal or superset of type 2 */
ecs_entity_t ecs_type_contains(
    const ecs_world_t *world,
    ecs_type_t type_1,
    ecs_type_t type_2,
    bool match_all,
    bool match_prefab)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    world = ecs_get_world(world);
    
    if (!type_1) {
        return 0;
    }

    ecs_assert(type_2 != NULL, ECS_INTERNAL_ERROR, NULL);

    if (type_1 == type_2) {
        return *(ecs_vector_first(type_1, ecs_entity_t));
    }

    int32_t i_2, i_1 = 0;
    ecs_entity_t e1 = 0;
    ecs_entity_t *t1_array = ecs_vector_first(type_1, ecs_entity_t);
    ecs_entity_t *t2_array = ecs_vector_first(type_2, ecs_entity_t);

    ecs_assert(t1_array != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(t2_array != NULL, ECS_INTERNAL_ERROR, NULL);

    int32_t t1_count = ecs_vector_count(type_1);
    int32_t t2_count = ecs_vector_count(type_2);

    for (i_2 = 0; i_2 < t2_count; i_2 ++) {
        ecs_entity_t e2 = t2_array[i_2];

        if (i_1 >= t1_count) {
            return 0;
        }

        e1 = t1_array[i_1];

        if (e2 > e1) {
            do {
                i_1 ++;
                if (i_1 >= t1_count) {
                    return 0;
                }
                e1 = t1_array[i_1];
            } while (e2 > e1);
        }

        if (e1 != e2) {
            if (match_prefab && e2 != 
                ecs_id(EcsName) && 
                e2 != EcsPrefab && e2 != EcsDisabled) 
            {
                if (ecs_find_entity_in_prefabs(world, 0, type_1, e2, 0)) {
                    e1 = e2;
                }
            }

            if (e1 != e2) {
                if (match_all) return 0;
            } else if (!match_all) {
                return e1;
            }
        } else {
            if (!match_all) return e1;
            i_1 ++;
            if (i_1 < t1_count) {
                e1 = t1_array[i_1];
            }
        }
    }

    if (match_all) {
        return e1;
    } else {
        return 0;
    }
}

/* -- Public API -- */

int32_t ecs_type_index_of(
    ecs_type_t type,
    ecs_entity_t entity)
{
    ecs_vector_each(type, ecs_entity_t, c_ptr, {
        if (*c_ptr == entity) {
            return c_ptr_i; 
        }
    });

    return -1;
}

ecs_type_t ecs_type_merge(
    ecs_world_t *world,
    ecs_type_t type,
    ecs_type_t to_add,
    ecs_type_t to_remove)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);

    /* This function is allowed while staged, as long as the type already
     * exists. If the type does not exist yet and traversing the table graph
     * results in the creation of a table, an assert will trigger. */    
    ecs_world_t *unsafe_world = (ecs_world_t*)ecs_get_world(world);
    
    ecs_table_t *table = ecs_table_from_type(unsafe_world, type);
    ecs_entities_t add_array = ecs_type_to_entities(to_add);
    ecs_entities_t remove_array = ecs_type_to_entities(to_remove);
    
    table = ecs_table_traverse_remove(
        unsafe_world, table, &remove_array, NULL); 

    table = ecs_table_traverse_add(
        unsafe_world, table, &add_array, NULL); 

    if (!table) {
        return NULL;
    } else {
        return table->type;
    }
}

ecs_type_t ecs_type_find(
    ecs_world_t *world,
    ecs_entity_t *array,
    int32_t count)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    
    /* This function is allowed while staged, as long as the type already
     * exists. If the type does not exist yet and traversing the table graph
     * results in the creation of a table, an assert will trigger. */    
    ecs_world_t *unsafe_world = (ecs_world_t*)ecs_get_world(world);

    ecs_entities_t entities = {
        .array = array,
        .count = count
    };

    ecs_table_t *table = ecs_table_find_or_create(unsafe_world, &entities);
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);

    return table->type;
}

static
bool has_pair(
    ecs_entity_t pair,
    ecs_entity_t e)
{
    return pair == ECS_PAIR_RELATION(e);
}

static
bool has_case(
    const ecs_world_t *world,
    ecs_entity_t sw_case,
    ecs_entity_t e)
{
    const EcsType *type_ptr = ecs_get(world, e & ECS_COMPONENT_MASK, EcsType);
    ecs_assert(type_ptr != NULL, ECS_INTERNAL_ERROR, NULL);
    return ecs_type_has_id(world, type_ptr->normalized, sw_case);
}

static
int match_id(
    const ecs_world_t *world,
    ecs_type_t type,
    ecs_entity_t id,
    ecs_entity_t match_with)
{
    if (ECS_HAS_ROLE(match_with, PAIR)) {
        ecs_entity_t rel = ECS_PAIR_RELATION(match_with);
        ecs_entity_t obj = ECS_PAIR_OBJECT(match_with);

        if (obj == EcsWildcard) {
            ecs_assert(rel != 0, ECS_INTERNAL_ERROR, NULL);
            
            if (!ECS_HAS_ROLE(id, PAIR) || !has_pair(rel, id)) {
                return 0;
            }

            ecs_entity_t *ids = ecs_vector_first(type, ecs_entity_t);
            int32_t i, count = ecs_vector_count(type);

            /* A pair with a (rel, *) requires the component that is the target
             * of the relation to also be present in the type. This must be
             * verified for each relation in the type, which is why the result
             * is a preliminary OK. If after a match a relation is found with an
             * object that doesn't match, the type doesn't match.
             *
             * This is legacy behavior. */
            ecs_entity_t comp = ECS_PAIR_OBJECT(id);
            for (i = 0; i < count; i ++) {
                if (comp == ids[i]) {
                    return 2;
                }
            }

            return -1;
        } else if (!rel) {
            if (ECS_HAS_ROLE(id, PAIR) && has_pair(obj, id)) {
                return 1;
            }
        }
    } else 
    if (ECS_HAS_ROLE(match_with, CASE)) {
        ecs_entity_t sw_case = match_with & ECS_COMPONENT_MASK;
        if (ECS_HAS_ROLE(id, SWITCH) && has_case(world, sw_case, id)) {
            return 1;
        } else {
            return 0;
        }
    }

    if (ECS_HAS(id, match_with)) {
        return 1;
    }

    return 0;
}

static
bool search_type(
    const ecs_world_t *world,
    ecs_type_t type,
    ecs_entity_t id,
    ecs_entity_t rel,
    int32_t min_depth,
    int32_t max_depth,
    int32_t depth,
    ecs_entity_t *out)
{
    if (!type) {
        return false;
    }

    if (!id) {
        return true;
    }

    if (max_depth && depth > max_depth) {
        return false;
    }

    ecs_entity_t *ids = ecs_vector_first(type, ecs_entity_t);
    int32_t i, count = ecs_vector_count(type);
    int matched = 0;

    if (depth >= min_depth) {
        for (i = 0; i < count; i ++) {
            int ret = match_id(world, type, ids[i], id);
            switch(ret) {
            case 0: break; /* no match, but keep looking */
            case 1: return true; /* match found */
            case -1: return false; /* no match found, stop looking */
            case 2: matched ++; break; /* match found, but need to keep looking */
            default: ecs_abort(ECS_INTERNAL_ERROR, NULL);
            }
        }
    }

    if (!matched && rel && id != EcsPrefab && id != EcsDisabled) {
        for (i = 0; i < count; i ++) {
            ecs_entity_t e = ids[i];
            if (!ECS_HAS_RELATION(e, rel)) {
                continue;
            }

            ecs_entity_t base = ecs_pair_object(world, e);
            if (!ecs_is_valid(world, base)) {
                /* This indicates that an entity has a relationship
                 * to an invalid base. That's no good, and will be handled with
                 * future features (e.g. automatically removing the relation) */
                continue;
            }

            ecs_type_t base_type = ecs_get_type(world, base);

            if (search_type(world, base_type, id, rel, 
                min_depth, max_depth, depth + 1, out)) 
            {
                if (out && !*out) {
                    *out = base;
                }
                return true;

            /* If the id could not be found on the base and the relationship is
             * not IsA, try substituting the base with IsA */
            } else if (rel != EcsIsA) {
                if (search_type(world, base_type, id, EcsIsA, 1, 0, 0, out)) {
                    if (out && !*out) {
                        *out = base;
                    }
                    return true;
                }
            }
        }
    }

    return matched != 0;
}

bool ecs_type_has_id(
    const ecs_world_t *world,
    ecs_type_t type,
    ecs_entity_t entity)
{
    return search_type(world, type, entity, EcsIsA, 0, 0, 0, NULL);
}

bool ecs_type_owns_id(
    const ecs_world_t *world,
    ecs_type_t type,
    ecs_entity_t entity,
    bool owned)
{
    return search_type(world, type, entity, owned ? 0 : EcsIsA, 0, 0, 0, NULL);
}

bool ecs_type_find_id(
    const ecs_world_t *world,
    ecs_type_t type,
    ecs_entity_t id,
    ecs_entity_t rel,
    int32_t min_depth,
    int32_t max_depth,
    ecs_entity_t *out)
{
    if (out) {
        *out = 0;
    }
    return search_type(world, type, id, rel, min_depth, max_depth, 0, out);
}

bool ecs_type_has_type(
    const ecs_world_t *world,
    ecs_type_t type,
    ecs_type_t has)
{
    return ecs_type_contains(world, type, has, true, false) != 0;
}

bool ecs_type_owns_type(
    const ecs_world_t *world,
    ecs_type_t type,
    ecs_type_t has,
    bool owned)
{
    return ecs_type_contains(world, type, has, true, !owned) != 0;
}

ecs_type_t ecs_type_add(
    ecs_world_t *world,
    ecs_type_t type,
    ecs_entity_t e)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);

    /* This function is allowed while staged, as long as the type already
     * exists. If the type does not exist yet and traversing the table graph
     * results in the creation of a table, an assert will trigger. */
    ecs_world_t *unsafe_world = (ecs_world_t*)ecs_get_world(world);

    ecs_table_t *table = ecs_table_from_type(unsafe_world, type);

    ecs_entities_t entities = {
        .array = &e,
        .count = 1
    };

    table = ecs_table_traverse_add(unsafe_world, table, &entities, NULL);

    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);

    return table->type;
}

ecs_type_t ecs_type_remove(
    ecs_world_t *world,
    ecs_type_t type,
    ecs_entity_t e)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    
    /* This function is allowed while staged, as long as the type already
     * exists. If the type does not exist yet and traversing the table graph
     * results in the creation of a table, an assert will trigger. */
    ecs_world_t *unsafe_world = (ecs_world_t*)ecs_get_world(world);
    
    ecs_table_t *table = ecs_table_from_type(unsafe_world, type);

    ecs_entities_t entities = {
        .array = &e,
        .count = 1
    };

    table = ecs_table_traverse_remove(unsafe_world, table, &entities, NULL);
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);

    return table->type;    
}

char* ecs_type_str(
    const ecs_world_t *world,
    ecs_type_t type)
{
    if (!type) {
        return ecs_os_strdup("");
    }

    ecs_vector_t *chbuf = ecs_vector_new(char, 32);
    char *dst;

    ecs_entity_t *entities = ecs_vector_first(type, ecs_entity_t);
    int32_t i, count = ecs_vector_count(type);

    for (i = 0; i < count; i ++) {
        ecs_entity_t e = entities[i];
        char buffer[256];
        ecs_size_t len;

        if (i) {
            *(char*)ecs_vector_add(&chbuf, char) = ',';
        }

        if (e == 1) {
            ecs_os_strcpy(buffer, "EcsComponent");
            len = ecs_os_strlen("EcsComponent");
        } else {
            len = ecs_from_size_t(ecs_id_str(world, e, buffer, 256));
        }

        dst = ecs_vector_addn(&chbuf, char, len);
        ecs_os_memcpy(dst, buffer, len);
    }

    *(char*)ecs_vector_add(&chbuf, char) = '\0';

    char* result = ecs_os_strdup(ecs_vector_first(chbuf, char));
    ecs_vector_free(chbuf);
    return result;
}

ecs_entity_t ecs_type_get_entity_for_xor(
    ecs_world_t *world,
    ecs_type_t type,
    ecs_entity_t xor)
{
    ecs_assert(
        ecs_type_owns_id(world, type, ECS_XOR | xor, true),
        ECS_INVALID_PARAMETER, NULL);

    const EcsType *type_ptr = ecs_get(world, xor, EcsType);
    ecs_assert(type_ptr != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_type_t xor_type = type_ptr->normalized;
    ecs_assert(xor_type != NULL, ECS_INTERNAL_ERROR, NULL);

    int32_t i, count = ecs_vector_count(type);
    ecs_entity_t *array = ecs_vector_first(type, ecs_entity_t);
    for (i = 0; i < count; i ++) {
        if (ecs_type_owns_id(world, xor_type, array[i], true)) {
            return array[i];
        }
    }

    return 0;
}

int32_t ecs_type_pair_index_of(
    ecs_type_t type, 
    int32_t start_index, 
    ecs_entity_t pair)
{
    int32_t i, count = ecs_vector_count(type);
    ecs_entity_t *array = ecs_vector_first(type, ecs_entity_t);

    for (i = start_index; i < count; i ++) {
        ecs_entity_t e = array[i];
        if (ECS_HAS_ROLE(e, PAIR)) {
            if (pair == ECS_PAIR_RELATION(e)) {
                return i;
            }
        }
    }

    return -1;
}

void ecs_os_api_impl(ecs_os_api_t *api);

static bool ecs_os_api_initialized = false;
static int ecs_os_api_init_count = 0;

ecs_os_api_t ecs_os_api;

int64_t ecs_os_api_malloc_count = 0;
int64_t ecs_os_api_realloc_count = 0;
int64_t ecs_os_api_calloc_count = 0;
int64_t ecs_os_api_free_count = 0;

void ecs_os_set_api(
    ecs_os_api_t *os_api)
{
    if (!ecs_os_api_initialized) {
        ecs_os_api = *os_api;
        ecs_os_api_initialized = true;
    }
}

void ecs_os_init(void)
{
    if (!ecs_os_api_initialized) {
        ecs_os_set_api_defaults();
    }
    
    if (!(ecs_os_api_init_count ++)) {
        if (ecs_os_api.init_) {
            ecs_os_api.init_();
        }
    }
}

void ecs_os_fini(void) {
    if (!--ecs_os_api_init_count) {
        if (ecs_os_api.fini_) {
            ecs_os_api.fini_();
        }
    }
}

static
void ecs_log(const char *fmt, va_list args) {
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
}

static
void ecs_log_error(const char *fmt, va_list args) {
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
}

static
void ecs_log_debug(const char *fmt, va_list args) {
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
}

static
void ecs_log_warning(const char *fmt, va_list args) {
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
}

void ecs_os_dbg(const char *fmt, ...) {
#ifndef NDEBUG
    va_list args;
    va_start(args, fmt);
    if (ecs_os_api.log_debug_) {
        ecs_os_api.log_debug_(fmt, args);
    }
    va_end(args);
#else
    (void)fmt;
#endif
}

void ecs_os_warn(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (ecs_os_api.log_warning_) {
        ecs_os_api.log_warning_(fmt, args);
    }
    va_end(args);
}

void ecs_os_log(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (ecs_os_api.log_) {
        ecs_os_api.log_(fmt, args);
    }
    va_end(args);
}

void ecs_os_err(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (ecs_os_api.log_error_) {
        ecs_os_api.log_error_(fmt, args);
    }
    va_end(args);
}

static
void ecs_os_gettime(ecs_time_t *time)
{
    uint64_t now = ecs_os_time_now();
    uint64_t sec = now / 1000000000;

    assert(sec < UINT32_MAX);
    assert((now - sec * 1000000000) < UINT32_MAX);

    time->sec = (uint32_t)sec;
    time->nanosec = (uint32_t)(now - sec * 1000000000);
}

static
void* ecs_os_api_malloc(ecs_size_t size) {
    ecs_os_api_malloc_count ++;
    ecs_assert(size > 0, ECS_INVALID_PARAMETER, NULL);
    return malloc((size_t)size);
}

static
void* ecs_os_api_calloc(ecs_size_t size) {
    ecs_os_api_calloc_count ++;
    ecs_assert(size > 0, ECS_INVALID_PARAMETER, NULL);
    return calloc(1, (size_t)size);
}

static
void* ecs_os_api_realloc(void *ptr, ecs_size_t size) {
    ecs_assert(size > 0, ECS_INVALID_PARAMETER, NULL);

    if (ptr) {
        ecs_os_api_realloc_count ++;
    } else {
        /* If not actually reallocing, treat as malloc */
        ecs_os_api_malloc_count ++; 
    }
    
    return realloc(ptr, (size_t)size);
}

static
void ecs_os_api_free(void *ptr) {
    if (ptr) {
        ecs_os_api_free_count ++;
    }
    free(ptr);
}

static
char* ecs_os_api_strdup(const char *str) {
    if (str) {
        int len = ecs_os_strlen(str);
        char *result = ecs_os_malloc(len + 1);
        ecs_assert(result != NULL, ECS_OUT_OF_MEMORY, NULL);
        ecs_os_strcpy(result, str);
        return result;
    } else {
        return NULL;
    }
}

/* Replace dots with underscores */
static
char *module_file_base(const char *module, char sep) {
    char *base = ecs_os_strdup(module);
    ecs_size_t i, len = ecs_os_strlen(base);
    for (i = 0; i < len; i ++) {
        if (base[i] == '.') {
            base[i] = sep;
        }
    }

    return base;
}

static
char* ecs_os_api_module_to_dl(const char *module) {
    ecs_strbuf_t lib = ECS_STRBUF_INIT;

    /* Best guess, use module name with underscores + OS library extension */
    char *file_base = module_file_base(module, '_');

#if defined(ECS_OS_LINUX)
    ecs_strbuf_appendstr(&lib, "lib");
    ecs_strbuf_appendstr(&lib, file_base);
    ecs_strbuf_appendstr(&lib, ".so");
#elif defined(ECS_OS_DARWIN)
    ecs_strbuf_appendstr(&lib, "lib");
    ecs_strbuf_appendstr(&lib, file_base);
    ecs_strbuf_appendstr(&lib, ".dylib");
#elif defined(ECS_OS_WINDOWS)
    ecs_strbuf_appendstr(&lib, file_base);
    ecs_strbuf_appendstr(&lib, ".dll");
#endif

    ecs_os_free(file_base);

    return ecs_strbuf_get(&lib);
}

static
char* ecs_os_api_module_to_etc(const char *module) {
    ecs_strbuf_t lib = ECS_STRBUF_INIT;

    /* Best guess, use module name with dashes + /etc */
    char *file_base = module_file_base(module, '-');

    ecs_strbuf_appendstr(&lib, file_base);
    ecs_strbuf_appendstr(&lib, "/etc");

    ecs_os_free(file_base);

    return ecs_strbuf_get(&lib);
}

void ecs_os_set_api_defaults(void)
{
    /* Don't overwrite if already initialized */
    if (ecs_os_api_initialized != 0) {
        return;
    }

    ecs_os_time_setup();
    
    /* Memory management */
    ecs_os_api.malloc_ = ecs_os_api_malloc;
    ecs_os_api.free_ = ecs_os_api_free;
    ecs_os_api.realloc_ = ecs_os_api_realloc;
    ecs_os_api.calloc_ = ecs_os_api_calloc;

    /* Strings */
    ecs_os_api.strdup_ = ecs_os_api_strdup;

    /* Time */
    ecs_os_api.sleep_ = ecs_os_time_sleep;
    ecs_os_api.get_time_ = ecs_os_gettime;

    /* Logging */
    ecs_os_api.log_ = ecs_log;
    ecs_os_api.log_error_ = ecs_log_error;
    ecs_os_api.log_debug_ = ecs_log_debug;
    ecs_os_api.log_warning_ = ecs_log_warning;

    /* Modules */
    if (!ecs_os_api.module_to_dl_) {
        ecs_os_api.module_to_dl_ = ecs_os_api_module_to_dl;
    }

    if (!ecs_os_api.module_to_etc_) {
        ecs_os_api.module_to_etc_ = ecs_os_api_module_to_etc;
    }

    ecs_os_api.abort_ = abort;
}

bool ecs_os_has_heap(void) {
    return 
        (ecs_os_api.malloc_ != NULL) &&
        (ecs_os_api.calloc_ != NULL) &&
        (ecs_os_api.realloc_ != NULL) &&
        (ecs_os_api.free_ != NULL);
}

bool ecs_os_has_threading(void) {
    return
        (ecs_os_api.mutex_new_ != NULL) &&
        (ecs_os_api.mutex_free_ != NULL) &&
        (ecs_os_api.mutex_lock_ != NULL) &&
        (ecs_os_api.mutex_unlock_ != NULL) &&
        (ecs_os_api.cond_new_ != NULL) &&
        (ecs_os_api.cond_free_ != NULL) &&
        (ecs_os_api.cond_wait_ != NULL) &&
        (ecs_os_api.cond_signal_ != NULL) &&
        (ecs_os_api.cond_broadcast_ != NULL) &&
        (ecs_os_api.thread_new_ != NULL) &&
        (ecs_os_api.thread_join_ != NULL);   
}

bool ecs_os_has_time(void) {
    return 
        (ecs_os_api.get_time_ != NULL) &&
        (ecs_os_api.sleep_ != NULL);
}

bool ecs_os_has_logging(void) {
    return 
        (ecs_os_api.log_ != NULL) &&
        (ecs_os_api.log_error_ != NULL) &&
        (ecs_os_api.log_debug_ != NULL) &&
        (ecs_os_api.log_warning_ != NULL);
}

bool ecs_os_has_dl(void) {
    return 
        (ecs_os_api.dlopen_ != NULL) &&
        (ecs_os_api.dlproc_ != NULL) &&
        (ecs_os_api.dlclose_ != NULL);  
}

bool ecs_os_has_modules(void) {
    return 
        (ecs_os_api.module_to_dl_ != NULL) &&
        (ecs_os_api.module_to_etc_ != NULL);
}

#ifdef FLECS_SYSTEMS_H
#endif

static
void activate_table(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_table_t *table,
    bool active);

#ifndef NDEBUG
static
ecs_entity_t get_cascade_component(
    ecs_query_t *query)
{
    return query->filter.terms[query->cascade_by - 1].id;
}
#endif

static
int32_t rank_by_depth(
    ecs_world_t *world,
    ecs_entity_t rank_by_component,
    ecs_type_t type)
{
    int32_t result = 0;
    int32_t i, count = ecs_vector_count(type);
    ecs_entity_t *array = ecs_vector_first(type, ecs_entity_t);

    for (i = count - 1; i >= 0; i --) {
        if (ECS_HAS_RELATION(array[i], EcsChildOf)) {
            ecs_type_t c_type = ecs_get_type(world, ecs_pair_object(world, array[i]));
            int32_t j, c_count = ecs_vector_count(c_type);
            ecs_entity_t *c_array = ecs_vector_first(c_type, ecs_entity_t);

            for (j = 0; j < c_count; j ++) {
                if (c_array[j] == rank_by_component) {
                    result ++;
                    result += rank_by_depth(world, rank_by_component, c_type);
                    break;
                }
            }

            if (j != c_count) {
                break;
            }
        } else if (!(array[i] & ECS_ROLE_MASK)) {
            /* No more parents after this */
            break;
        }
    }

    return result;
}

static
int table_compare(
    const void *t1,
    const void *t2)
{
    const ecs_matched_table_t *table_1 = t1;
    const ecs_matched_table_t *table_2 = t2;

    return table_1->rank - table_2->rank;
}

static
bool has_auto_activation(
    ecs_query_t *q)
{
    /* Only a basic query with no additional features does table activation */
    return !(q->flags & EcsQueryNoActivation);
}

static
void order_ranked_tables(
    ecs_world_t *world,
    ecs_query_t *query)
{
    if (query->group_table) {
        ecs_vector_sort(query->tables, ecs_matched_table_t, table_compare);       

        /* Recompute the table indices by first resetting all indices, and then
         * re-adding them one by one. */
        if (has_auto_activation(query)) { 
            ecs_map_iter_t it = ecs_map_iter(query->table_indices);
            ecs_table_indices_t *ti;
            while ((ti = ecs_map_next(&it, ecs_table_indices_t, NULL))) {
                /* If table is registered, it must have at least one index */
                int32_t count = ti->count;
                ecs_assert(count > 0, ECS_INTERNAL_ERROR, NULL);
                (void)count;

                /* Only active tables are reordered, so don't reset inactive 
                 * tables */
                if (ti->indices[0] >= 0) {
                    ti->count = 0;
                }
            }
        }

        /* Re-register monitors after tables have been reordered. This will update
         * the table administration with the new matched_table ids, so that when a
         * monitor is executed we can quickly find the right matched_table. */
        if (query->flags & EcsQueryMonitor) { 
            ecs_vector_each(query->tables, ecs_matched_table_t, table, {        
                ecs_table_notify(world, table->iter_data.table, &(ecs_table_event_t){
                    .kind = EcsTableQueryMatch,
                    .query = query,
                    .matched_table_index = table_i
                });
            });
        }

        /* Update table index */
        if (has_auto_activation(query)) {
            ecs_vector_each(query->tables, ecs_matched_table_t, table, {  
                ecs_table_indices_t *ti = ecs_map_get(query->table_indices, 
                    ecs_table_indices_t, table->iter_data.table->id);

                ecs_assert(ti != NULL, ECS_INTERNAL_ERROR, NULL);
                ti->indices[ti->count] = table_i;
                ti->count ++;
            });
        }
    }
    
    query->match_count ++;
    query->needs_reorder = false;
}

static
void group_table(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_matched_table_t *table)
{
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);

    if (query->group_table) {
        ecs_assert(table->iter_data.table != NULL, ECS_INTERNAL_ERROR, NULL);
        table->rank = query->group_table(
            world, query->rank_on_component, table->iter_data.table->type);
    } else {
        table->rank = 0;
    }
}

/* Rank all tables of query. Only necessary if a new ranking function was
 * provided or if a monitored entity set the component used for ranking. */
static
void group_tables(
    ecs_world_t *world,
    ecs_query_t *query)
{
    if (query->group_table) {
        ecs_vector_each(query->tables, ecs_matched_table_t, table, {
            group_table(world, query, table);
        });

        ecs_vector_each(query->empty_tables, ecs_matched_table_t, table, {
            group_table(world, query, table);
        });              
    }
}

#ifndef NDEBUG

static
const char* query_name(
    ecs_world_t *world,
    ecs_query_t *q)
{
    if (q->system) {
        return ecs_get_name(world, q->system);
    } else if (q->filter.name) {
        return q->filter.name;
    } else {
        return q->filter.expr;
    }
}

#endif

static
int get_comp_and_src(
    ecs_world_t *world,
    ecs_query_t *query,
    int32_t t,
    ecs_type_t table_type,
    ecs_entity_t *component_out,
    ecs_entity_t *entity_out)
{
    ecs_entity_t component = 0, entity = 0;

    ecs_term_t *terms = query->filter.terms;
    int32_t term_count = query->filter.term_count;
    ecs_term_t *term = &terms[t];
    ecs_term_id_t *subj = &term->args[0];
    ecs_oper_kind_t op = term->oper;

    if (op == EcsNot) {
        entity = subj->entity;
    }

    if (!subj->entity) {
        component = term->id;
    } else {
        ecs_type_t type = table_type;
        if (subj->entity != EcsThis) {
            type = ecs_get_type(world, subj->entity);
        }

        if (op == EcsOr) {
            for (; t < term_count; t ++) {
                term = &terms[t];

                /* Keep iterating until the next non-OR expression */
                if (term->oper != EcsOr) {
                    t --;
                    break;
                }

                if (!component) {
                    ecs_entity_t source = 0;
                    bool result = ecs_type_find_id(world, type, term->id, 
                        subj->relation, subj->min_depth, subj->max_depth, 
                        &source);

                    if (result) {
                        component = term->id;
                    }

                    if (source) {
                        entity = source;
                    }                    
                }
            }
        } else {
            component = term->id;

            ecs_entity_t source = 0;
            bool result = ecs_type_find_id(world, type, component, 
                subj->relation, subj->min_depth, subj->max_depth, &source);

            if (op == EcsNot) {
                result = !result;
            }

            /* Optional terms may not have the component. *From terms contain
             * the id of a type of which the contents must match, but the type
             * itself does not need to match. */
            if (op == EcsOptional || op == EcsAndFrom || op == EcsOrFrom || 
                op == EcsNotFrom) 
            {
                result = true;
            }

            /* Table has already been matched, so unless column is optional
             * any components matched from the table must be available. */
            if (type == table_type) {
                ecs_assert(result == true, ECS_INTERNAL_ERROR, NULL);
            }

            if (source) {
                entity = source;
            }
        }

        if (subj->entity != EcsThis) {
            entity = subj->entity;
        }
    }

    if (entity == EcsThis) {
        entity = 0;
    }

    *component_out = component;
    *entity_out = entity;

    return t;
}

typedef struct trait_offset_t {
    int32_t index;
    int32_t count;
} trait_offset_t;

/* Get index for specified trait. Take into account that a trait can be matched
 * multiple times per table, by keeping an offset of the last found index */
static
int32_t get_trait_index(
    ecs_type_t table_type,
    ecs_entity_t component,
    int32_t column_index,
    trait_offset_t *trait_offsets,
    int32_t count)
{
    int32_t result;

    /* The count variable keeps track of the number of times a trait has been
     * matched with the current table. Compare the count to check if the index
     * was already resolved for this iteration */
    if (trait_offsets[column_index].count == count) {
        /* If it was resolved, return the last stored index. Subtract one as the
         * index is offset by one, to ensure we're not getting stuck on the same
         * index. */
        result = trait_offsets[column_index].index - 1;
    } else {
        /* First time for this iteration that the trait index is resolved, look
         * it up in the type. */
        result = ecs_type_pair_index_of(table_type, 
            trait_offsets[column_index].index, component);
        trait_offsets[column_index].index = result + 1;
        trait_offsets[column_index].count = count;
    }
    
    return result;
}

static
int32_t get_component_index(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_type_t table_type,
    ecs_entity_t *component_out,
    int32_t column_index,
    ecs_oper_kind_t op,
    trait_offset_t *trait_offsets,
    int32_t count)
{
    int32_t result = 0;
    ecs_entity_t component = *component_out;

    if (component) {
        /* If requested component is a case, find the corresponding switch to
         * lookup in the table */
        if (ECS_HAS_ROLE(component, CASE)) {
            result = ecs_table_switch_from_case(
                world, table, component);
            ecs_assert(result != -1, ECS_INTERNAL_ERROR, NULL);

            result += table->sw_column_offset;
        } else
        if (ECS_HAS_ROLE(component, PAIR)) { 
            /* If only the lo part of the trait identifier is set, interpret it
             * as the trait to match. This will match any instance of the trait
             * on the entity and in a signature looks like "PAIR | MyTrait". */
            if (!ECS_PAIR_RELATION(component)) {
                ecs_assert(trait_offsets != NULL, ECS_INTERNAL_ERROR, NULL);

                /* Strip the PAIR role */
                component &= ECS_COMPONENT_MASK;

                /* Get index of trait. Start looking from the last trait index
                 * as this may not be the first instance of the trait. */
                result = get_trait_index(
                    table_type, component, column_index, trait_offsets, count);
                
                if (result != -1) {
                    /* If component of current column is a trait, get the actual 
                     * trait type for the table, so the system can see which 
                     * component the trait was applied to */   
                    ecs_entity_t *trait = ecs_vector_get(
                        table_type, ecs_entity_t, result);
                    *component_out = *trait;

                    /* Check if the trait is a tag or whether it has data */
                    if (ecs_get(world, component, EcsComponent) == NULL) {
                        /* If trait has no data associated with it, use the
                         * component to which the trait has been added */
                        component = ecs_entity_t_lo(*trait);
                    }
                }
            } else {
                /* If trait does have the hi part of the identifier set, this is
                 * a fully qualified trait identifier. In a signature this looks
                 * like "PAIR | MyTrait > Comp". */
                ecs_entity_t lo = ecs_entity_t_lo(component);
                if (lo == EcsWildcard) {
                    ecs_assert(trait_offsets != NULL, ECS_INTERNAL_ERROR, NULL);

                    /* Get id for the trait to lookup by taking the trait from
                     * the high 32 bits, move it to the low 32 bits, and reapply
                     * the PAIR mask. */
                    component = ECS_PAIR_RELATION(component);

                    /* If the low part of the identifier is the wildcard entity,
                     * this column is requesting the component to which the 
                     * trait is applied. First, find the component identifier */
                    result = get_trait_index(table_type, component, 
                        column_index, trait_offsets, count);

                    /* Type must have the trait, otherwise table would not have
                     * matched */
                    ecs_assert(result != -1, ECS_INTERNAL_ERROR, NULL);

                    /* Get component id at returned index */
                    ecs_entity_t *trait = ecs_vector_get(
                        table_type, ecs_entity_t, result);
                    ecs_assert(trait != NULL, ECS_INTERNAL_ERROR, NULL);

                    /* Get the lower part of the trait id. This is the component
                     * we're looking for. */
                    component = ecs_entity_t_lo(*trait);
                    *component_out = component;

                    /* Now lookup the component as usual */
                }

                /* If the low part is a regular entity (component), then
                 * this query exactly matches a single trait instance. In
                 * this case we can simply do a lookup of the trait 
                 * identifier in the table type. */
                result = ecs_type_index_of(table_type, component);
            }
        } else {
            /* Get column index for component */
            result = ecs_type_index_of(table_type, component);
        }

        /* If column is found, add one to the index, as column zero in
        * a table is reserved for entity id's */
        if (result != -1) {
            result ++;
        }     

        /* ecs_table_column_offset may return -1 if the component comes
         * from a prefab. If so, the component will be resolved as a
         * reference (see below) */           
    }

    if (op == EcsAndFrom || op == EcsOrFrom || op == EcsNotFrom) {
        result = 0;
    } else if (op == EcsOptional) {
        /* If table doesn't have the field, mark it as no data */
        if (!ecs_type_has_id(world, table_type, component)) {
            result = 0;
        }
    }  

    return result;
}

static
ecs_vector_t* add_ref(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_vector_t *references,
    ecs_term_t *term,
    ecs_entity_t component,
    ecs_entity_t entity)
{
    const EcsComponent *c_info = ecs_get(world, component, EcsComponent);
    
    ecs_ref_t *ref = ecs_vector_add(&references, ecs_ref_t);
    ecs_term_id_t *subj = &term->args[0];

    if (!(subj->set & EcsAll)) {
        ecs_assert(entity != 0, ECS_INTERNAL_ERROR, NULL);
    }
    
    *ref = (ecs_ref_t){0};
    ref->entity = entity;
    ref->component = component;

    if (ecs_has(world, term->id, EcsComponent)) {
        if (c_info->size && subj->entity != 0) {
            if (entity) {
                ecs_get_ref_w_id(world, ref, entity, component);
                ecs_set_watch(world, entity);
            }

            query->flags |= EcsQueryHasRefs;
        }
    }

    return references;
}

static
ecs_entity_t is_column_trait(
    ecs_term_t *term)
{
    ecs_entity_t c = term->id;
    if (c) {
        if (ECS_HAS_ROLE(c, PAIR)) {
            if (!ECS_PAIR_RELATION(c)) {
                return c;
            } else
            if (ECS_PAIR_OBJECT(c) == EcsWildcard) {
                return ECS_PAIR_RELATION(c);
            }
        }
    }

    return 0;
}

static
int32_t type_trait_count(
    ecs_type_t type,
    ecs_entity_t trait)
{
    int32_t i, count = ecs_vector_count(type);
    ecs_entity_t *entities = ecs_vector_first(type, ecs_entity_t);
    int32_t result = 0;

    trait &= ECS_COMPONENT_MASK;

    for (i = 0; i < count; i ++) {
        ecs_entity_t e = entities[i];
        if (ECS_HAS_ROLE(e, PAIR)) {
            if (ECS_PAIR_RELATION(e) == trait) {
                result ++;
            }
        }
    }

    return result;
}

/* For each trait that the query subscribes for, count the occurrences in the
 * table. Cardinality of subscribed for traits must be the same as in the table
 * or else the table won't match. */
static
int32_t count_traits(
    const ecs_query_t *query,
    ecs_type_t type)
{
    ecs_term_t *terms = query->filter.terms;
    int32_t i, count = query->filter.term_count;
    int32_t first_count = 0, trait_count = 0;

    for (i = 0; i < count; i ++) {
        ecs_entity_t trait = is_column_trait(&terms[i]);
        if (trait) {
            trait_count = type_trait_count(type, trait);
            if (!first_count) {
                first_count = trait_count;
            } else {
                if (first_count != trait_count) {
                    /* The traits that this query subscribed for occur in the
                     * table but don't have the same cardinality. Ignore the
                     * table. This could typically happen for empty tables along
                     * a path in the table graph. */
                    return -1;
                }
            }
        }
    }

    return first_count;
}

static
ecs_type_t get_term_type(
    ecs_world_t *world,
    ecs_term_t *term,
    ecs_entity_t component)
{
    ecs_oper_kind_t oper = term->oper;

    if (oper == EcsAndFrom || oper == EcsOrFrom || oper == EcsNotFrom) {
        const EcsType *type = ecs_get(world, component, EcsType);
        if (type) {
            return type->normalized;
        } else {
            return ecs_get_type(world, component);
        }
    } else {
        return ecs_type_from_id(world, component);
    }    
}

/** Add table to system, compute offsets for system components in table it */
static
void add_table(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_table_t *table)
{
    ecs_type_t table_type = NULL;
    ecs_term_t *terms = query->filter.terms;
    int32_t t, c, term_count = query->filter.term_count;

    if (table) {
        table_type = table->type;
    }

    int32_t trait_cur = 0, trait_count = count_traits(query, table_type);
    
    /* If the query has traits, we need to account for the fact that a table may
     * have multiple components to which the trait is applied, which means the
     * table has to be registered with the query multiple times, with different
     * table columns. If so, allocate a small array for each trait in which the
     * last added table index of the trait is stored, so that in the next 
     * iteration we can start the search from the correct offset type. */
    trait_offset_t *trait_offsets = NULL;
    if (trait_count) {
        trait_offsets = ecs_os_calloc(
            ECS_SIZEOF(trait_offset_t) * term_count);
    }

    /* From here we recurse */
    int32_t *table_indices = NULL;
    int32_t table_indices_count = 0;
    int32_t matched_table_index = 0;
    ecs_matched_table_t table_data;
    ecs_vector_t *references = NULL;

add_trait:
    table_data = (ecs_matched_table_t){ .iter_data.table = table };
    if (table) {
        table_type = table->type;
    }

    /* If grouping is enabled for query, assign the group rank to the table */
    group_table(world, query, &table_data);

    if (term_count) {
        /* Array that contains the system column to table column mapping */
        table_data.iter_data.columns = ecs_os_malloc(ECS_SIZEOF(int32_t) * query->filter.term_count_actual);
        ecs_assert(table_data.iter_data.columns != NULL, ECS_OUT_OF_MEMORY, NULL);

        /* Store the components of the matched table. In the case of OR expressions,
        * components may differ per matched table. */
        table_data.iter_data.components = ecs_os_malloc(ECS_SIZEOF(ecs_entity_t) * query->filter.term_count_actual);
        ecs_assert(table_data.iter_data.components != NULL, ECS_OUT_OF_MEMORY, NULL);

        /* Also cache types, so no lookup is needed while iterating */
        table_data.iter_data.types = ecs_os_malloc(ECS_SIZEOF(ecs_type_t) * query->filter.term_count_actual);
        ecs_assert(table_data.iter_data.types != NULL, ECS_OUT_OF_MEMORY, NULL);        
    }

    /* Walk columns parsed from the system signature */
    c = 0;
    for (t = 0; t < term_count; t ++) {
        ecs_term_t *term = &terms[t];
        ecs_term_id_t subj = term->args[0];
        ecs_entity_t entity = 0, component = 0;
        ecs_oper_kind_t op = term->oper;

        if (op == EcsNot) {
            subj.entity = 0;
        }

        table_data.iter_data.columns[c] = 0;

        /* Get actual component and component source for current column */
        t = get_comp_and_src(world, query, t, table_type, &component, &entity);

        /* This column does not retrieve data from a static entity */
        if (!entity && subj.entity) {
            int32_t index = get_component_index(world, table, table_type, 
                &component, c, op, trait_offsets, trait_cur + 1);

            if (index == -1) {
                if (op == EcsOptional && subj.set == EcsSelf) {
                    index = 0;
                }
            } else {
                if (op == EcsOptional && !(subj.set & EcsSelf)) {
                    index = 0;
                }
            }

            table_data.iter_data.columns[c] = index;

            /* If the column is a case, we should only iterate the entities in
             * the column for this specific case. Add a sparse column with the
             * case id so we can find the correct entities when iterating */
            if (ECS_HAS_ROLE(component, CASE)) {
                ecs_sparse_column_t *sc = ecs_vector_add(
                    &table_data.sparse_columns, ecs_sparse_column_t);
                sc->signature_column_index = t;
                sc->sw_case = component & ECS_COMPONENT_MASK;
                sc->sw_column = NULL;
            }

            /* If table has a disabled bitmask for components, check if there is
             * a disabled column for the queried for component. If so, cache it
             * in a vector as the iterator will need to skip the entity when the
             * component is disabled. */
            if (index && (table && table->flags & EcsTableHasDisabled)) {
                ecs_entity_t bs_id = 
                    (component & ECS_COMPONENT_MASK) | ECS_DISABLED;
                int32_t bs_index = ecs_type_index_of(table->type, bs_id);
                if (bs_index != -1) {
                    ecs_bitset_column_t *elem = ecs_vector_add(
                        &table_data.bitset_columns, ecs_bitset_column_t);
                    elem->column_index = bs_index;
                    elem->bs_column = NULL;
                }
            }
        }

        if ((entity || table_data.iter_data.columns[c] == -1 || subj.set & EcsAll)) {
            references = add_ref(world, query, references, term,
                component, entity);
            table_data.iter_data.columns[c] = -ecs_vector_count(references);
        }

        ecs_entity_t type_id = ecs_get_typeid(world, component);
        if (type_id) {
            const EcsComponent *cptr = ecs_get(world, type_id, EcsComponent);
            if (!cptr || !cptr->size) {
                int32_t column = table_data.iter_data.columns[c];
                if (column > 0) {
                    table_data.iter_data.columns[c] = 0;
                } else if (column) {
                    ecs_ref_t *r = ecs_vector_get(
                        references, ecs_ref_t, -column - 1);
                    r->component = 0;
                }
            }
        }

        table_data.iter_data.components[c] = component;
        table_data.iter_data.types[c] = get_term_type(world, term, component);

        c ++;
    }

    /* Initially always add table to inactive group. If the system is registered
     * with the table and the table is not empty, the table will send an
     * activate signal to the system. */

    ecs_matched_table_t *table_elem;
    if (table && has_auto_activation(query)) {
        table_elem = ecs_vector_add(&query->empty_tables, 
            ecs_matched_table_t);

        /* Store table index */
        matched_table_index = ecs_vector_count(query->empty_tables);
        table_indices_count ++;
        table_indices = ecs_os_realloc(
            table_indices, table_indices_count * ECS_SIZEOF(int32_t));
        table_indices[table_indices_count - 1] = -matched_table_index;

        #ifndef NDEBUG
        char *type_expr = ecs_type_str(world, table->type);
        ecs_trace_2("query #[green]%s#[reset] matched with table #[green][%s]",
            query_name(world, query), type_expr);
        ecs_os_free(type_expr);
        #endif
    } else {
        /* If no table is provided to function, this is a system that contains
         * no columns that require table matching. In this case, the system will
         * only have one "dummy" table that caches data from the system columns.
         * Always add this dummy table to the list of active tables, since it
         * would never get activated otherwise. */
        table_elem = ecs_vector_add(&query->tables, ecs_matched_table_t);

        /* If query doesn't automatically activates/inactivates tables, we can 
         * get the count to determine the current table index. */
        matched_table_index = ecs_vector_count(query->tables) - 1;
        ecs_assert(matched_table_index >= 0, ECS_INTERNAL_ERROR, NULL);
    }

    if (references) {
        ecs_size_t ref_size = ECS_SIZEOF(ecs_ref_t) * ecs_vector_count(references);
        table_data.iter_data.references = ecs_os_malloc(ref_size);
        ecs_os_memcpy(table_data.iter_data.references, 
            ecs_vector_first(references, ecs_ref_t), ref_size);
        ecs_vector_free(references);
        references = NULL;
    }

    *table_elem = table_data;

    /* Use tail recursion when adding table for multiple traits */
    trait_cur ++;
    if (trait_cur < trait_count) {
        goto add_trait;
    }

    /* Register table indices before sending out the match signal. This signal
     * can cause table activation, and table indices are needed for that. */
    if (table_indices) {
        ecs_table_indices_t *ti = ecs_map_ensure(
            query->table_indices, ecs_table_indices_t, table->id);
        if (ti->indices) {
            ecs_os_free(ti->indices);
        }
        ti->indices = table_indices;
        ti->count = table_indices_count;
    }

    if (table && !(query->flags & EcsQueryIsSubquery)) {
        ecs_table_notify(world, table, &(ecs_table_event_t){
            .kind = EcsTableQueryMatch,
            .query = query,
            .matched_table_index = matched_table_index
        });
    } else if (table && ecs_table_count(table)) {
        activate_table(world, query, table, true);
    }

    if (trait_offsets) {
        ecs_os_free(trait_offsets);
    }
}

static
bool match_term(
    const ecs_world_t *world,
    ecs_type_t type,
    ecs_term_t *term,
    ecs_match_failure_t *failure_info)
{
    (void)failure_info;

    ecs_term_id_t *subj = &term->args[0];
    uint8_t set = subj->set;

    /* If term has no subject, there's nothing to match */
    if (!subj->entity) {
        return true;
    }

    if (term->args[0].entity != EcsThis) {
        type = ecs_get_type(world, subj->entity);
    }

    if (!set) {
        set = EcsSelf;
    }

    return ecs_type_find_id(
        world, type, term->id, subj->relation, 
        subj->min_depth, subj->max_depth, NULL);
}

/* Match table with query */
bool ecs_query_match(
    const ecs_world_t *world,
    const ecs_table_t *table,
    const ecs_query_t *query,
    ecs_match_failure_t *failure_info)
{
    /* Prevent having to add if not null checks everywhere */
    ecs_match_failure_t tmp_failure_info;
    if (!failure_info) {
        failure_info = &tmp_failure_info;
    }

    failure_info->reason = EcsMatchOk;
    failure_info->column = 0;

    if (!(query->flags & EcsQueryNeedsTables)) {
        failure_info->reason = EcsMatchSystemIsATask;
        return false;
    }

    ecs_type_t table_type = table->type;

    /* Don't match disabled entities */
    if (!(query->flags & EcsQueryMatchDisabled) && ecs_type_owns_id(
        world, table_type, EcsDisabled, true))
    {
        failure_info->reason = EcsMatchEntityIsDisabled;
        return false;
    }

    /* Don't match prefab entities */
    if (!(query->flags & EcsQueryMatchPrefab) && ecs_type_owns_id(
        world, table_type, EcsPrefab, true))
    {
        failure_info->reason = EcsMatchEntityIsPrefab;
        return false;
    }

    /* Check if trait cardinality matches traits in query, if any */
    if (count_traits(query, table->type) == -1) {
        return false;
    }

    ecs_term_t *terms = query->filter.terms;
    int32_t i, term_count = query->filter.term_count;

    for (i = 0; i < term_count; i ++) {
        ecs_term_t *term = &terms[i];
        ecs_oper_kind_t oper = term->oper;

        failure_info->column = i + 1;

        if (oper == EcsAnd) {
            if (!match_term(world, table_type, term, failure_info)) {
                return false;
            }

        } else if (oper == EcsNot) {
            if (match_term(world, table_type, term, failure_info)) {
                return false;
            }

        } else if (oper == EcsOr) {
            bool match = false;

            for (; i < term_count; i ++) {
                term = &terms[i];
                if (term->oper != EcsOr) {
                    i --;
                    break;
                }

                if (!match && match_term(
                    world, table_type, term, failure_info))
                {
                    match = true;
                }
            }

            if (!match) {
                return false;
            }
 
        } else if (oper == EcsAndFrom || oper == EcsOrFrom || oper == EcsNotFrom) {
            ecs_type_t type = get_term_type((ecs_world_t*)world, term, term->id);
            int32_t match_count = 0, j, count = ecs_vector_count(type);
            ecs_entity_t *ids = ecs_vector_first(type, ecs_entity_t);

            for (j = 0; j < count; j ++) {
                ecs_term_t tmp_term = *term;
                tmp_term.oper = EcsAnd;
                tmp_term.id = ids[j];
                tmp_term.pred.entity = ids[j];

                if (match_term(world, table_type, &tmp_term, failure_info)) {
                    match_count ++;
                }
            }

            if (oper == EcsAndFrom && match_count != count) {
                return false;
            }
            if (oper == EcsOrFrom && match_count == 0) {
                return false;
            }
            if (oper == EcsNotFrom && match_count != 0) {
                return false;
            }
        }
    }

    return true;
}

/** Match existing tables against system (table is created before system) */
static
void match_tables(
    ecs_world_t *world,
    ecs_query_t *query)
{
    int32_t i, count = ecs_sparse_count(world->store.tables);

    for (i = 0; i < count; i ++) {
        ecs_table_t *table = ecs_sparse_get(
            world->store.tables, ecs_table_t, i);

        if (ecs_query_match(world, table, query, NULL)) {
            add_table(world, query, table);
        }
    }

    order_ranked_tables(world, query);
}

#define ELEM(ptr, size, index) ECS_OFFSET(ptr, size * index)

static
int32_t qsort_partition(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data,
    ecs_entity_t *entities,
    void *ptr,    
    int32_t elem_size,
    int32_t lo,
    int32_t hi,
    ecs_compare_action_t compare)
{
    int32_t p = (hi + lo) / 2;
    void *pivot = ELEM(ptr, elem_size, p);
    ecs_entity_t pivot_e = entities[p];
    int32_t i = lo - 1, j = hi + 1;
    void *el;    

repeat:
    {
        do {
            i ++;
            el = ELEM(ptr, elem_size, i);
        } while ( compare(entities[i], el, pivot_e, pivot) < 0);

        do {
            j --;
            el = ELEM(ptr, elem_size, j);
        } while ( compare(entities[j], el, pivot_e, pivot) > 0);

        if (i >= j) {
            return j;
        }

        ecs_table_swap(world, table, data, i, j);

        if (p == i) {
            pivot = ELEM(ptr, elem_size, j);
            pivot_e = entities[j];
        } else if (p == j) {
            pivot = ELEM(ptr, elem_size, i);
            pivot_e = entities[i];
        }

        goto repeat;
    }
}

static
void qsort_array(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_data_t *data,
    ecs_entity_t *entities,
    void *ptr,
    int32_t size,
    int32_t lo,
    int32_t hi,
    ecs_compare_action_t compare)
{   
    if ((hi - lo) < 1)  {
        return;
    }

    int32_t p = qsort_partition(
        world, table, data, entities, ptr, size, lo, hi, compare);

    qsort_array(world, table, data, entities, ptr, size, lo, p, compare);

    qsort_array(world, table, data, entities, ptr, size, p + 1, hi, compare); 
}

static
void sort_table(
    ecs_world_t *world,
    ecs_table_t *table,
    int32_t column_index,
    ecs_compare_action_t compare)
{
    ecs_data_t *data = ecs_table_get_data(table);
    if (!data || !data->entities) {
        /* Nothing to sort */
        return;
    }

    int32_t count = ecs_table_data_count(data);
    if (count < 2) {
        return;
    }

    ecs_entity_t *entities = ecs_vector_first(data->entities, ecs_entity_t);

    void *ptr = NULL;
    int32_t size = 0;
    if (column_index != -1) {
        ecs_column_t *column = &data->columns[column_index];
        size = column->size;
        ptr = ecs_vector_first_t(column->data, size, column->alignment);
    }

    qsort_array(world, table, data, entities, ptr, size, 0, count - 1, compare);
}

/* Helper struct for building sorted table ranges */
typedef struct sort_helper_t {
    ecs_matched_table_t *table;
    ecs_entity_t *entities;
    const void *ptr;
    int32_t row;
    int32_t elem_size;
    int32_t count;
    bool shared;
} sort_helper_t;

static
const void* ptr_from_helper(
    sort_helper_t *helper)
{
    ecs_assert(helper->row < helper->count, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(helper->elem_size >= 0, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(helper->row >= 0, ECS_INTERNAL_ERROR, NULL);
    if (helper->shared) {
        return helper->ptr;
    } else {
        return ELEM(helper->ptr, helper->elem_size, helper->row);
    }
}

static
ecs_entity_t e_from_helper(
    sort_helper_t *helper)
{
    if (helper->row < helper->count) {
        return helper->entities[helper->row];
    } else {
        return 0;
    }
}

static
void build_sorted_table_range(
    ecs_query_t *query,
    int32_t start,
    int32_t end)
{
    ecs_world_t *world = query->world;
    ecs_entity_t component = query->sort_on_component;
    ecs_compare_action_t compare = query->compare;

    /* Fetch data from all matched tables */
    ecs_matched_table_t *tables = ecs_vector_first(query->tables, ecs_matched_table_t);
    sort_helper_t *helper = ecs_os_malloc((end - start) * ECS_SIZEOF(sort_helper_t));

    int i, to_sort = 0;
    for (i = start; i < end; i ++) {
        ecs_matched_table_t *table_data = &tables[i];
        ecs_table_t *table = table_data->iter_data.table;
        ecs_data_t *data = ecs_table_get_data(table);
        ecs_vector_t *entities;
        if (!data || !(entities = data->entities) || !ecs_table_count(table)) {
            continue;
        }

        int32_t index = ecs_type_index_of(table->type, component);
        if (index != -1) {
            ecs_column_t *column = &data->columns[index];
            int16_t size = column->size;
            int16_t align = column->alignment;
            helper[to_sort].ptr = ecs_vector_first_t(column->data, size, align);
            helper[to_sort].elem_size = size;
            helper[to_sort].shared = false;
        } else if (component) {
            /* Find component in prefab */
            ecs_entity_t base = ecs_find_entity_in_prefabs(
                world, 0, table->type, component, 0);
            
            /* If a base was not found, the query should not have allowed using
             * the component for sorting */
            ecs_assert(base != 0, ECS_INTERNAL_ERROR, NULL);

            const EcsComponent *cptr = ecs_get(world, component, EcsComponent);
            ecs_assert(cptr != NULL, ECS_INTERNAL_ERROR, NULL);

            helper[to_sort].ptr = ecs_get_w_id(world, base, component);
            helper[to_sort].elem_size = cptr->size;
            helper[to_sort].shared = true;
        } else {
            helper[to_sort].ptr = NULL;
            helper[to_sort].elem_size = 0;
            helper[to_sort].shared = false;
        }

        helper[to_sort].table = table_data;
        helper[to_sort].entities = ecs_vector_first(entities, ecs_entity_t);
        helper[to_sort].row = 0;
        helper[to_sort].count = ecs_table_count(table);
        to_sort ++;      
    }

    ecs_table_slice_t *cur = NULL;

    bool proceed;
    do {
        int32_t j, min = 0;
        proceed = true;

        ecs_entity_t e1;
        while (!(e1 = e_from_helper(&helper[min]))) {
            min ++;
            if (min == to_sort) {
                proceed = false;
                break;
            }
        }

        if (!proceed) {
            break;
        }

        for (j = min + 1; j < to_sort; j++) {
            ecs_entity_t e2 = e_from_helper(&helper[j]);
            if (!e2) {
                continue;
            }

            const void *ptr1 = ptr_from_helper(&helper[min]);
            const void *ptr2 = ptr_from_helper(&helper[j]);

            if (compare(e1, ptr1, e2, ptr2) > 0) {
                min = j;
                e1 = e_from_helper(&helper[min]);
            }
        }

        sort_helper_t *cur_helper = &helper[min];
        if (!cur || cur->table != cur_helper->table) {
            cur = ecs_vector_add(&query->table_slices, ecs_table_slice_t);
            ecs_assert(cur != NULL, ECS_INTERNAL_ERROR, NULL);
            cur->table = cur_helper->table;
            cur->start_row = cur_helper->row;
            cur->count = 1;
        } else {
            cur->count ++;
        }

        cur_helper->row ++;
    } while (proceed);

    ecs_os_free(helper);
}

static
void build_sorted_tables(
    ecs_query_t *query)
{
    /* Clean previous sorted tables */
    ecs_vector_free(query->table_slices);
    query->table_slices = NULL;

    int32_t i, count = ecs_vector_count(query->tables);
    ecs_matched_table_t *tables = ecs_vector_first(query->tables, ecs_matched_table_t);
    ecs_matched_table_t *table = NULL;

    int32_t start = 0, rank = 0;
    for (i = 0; i < count; i ++) {
        table = &tables[i];
        if (rank != table->rank) {
            if (start != i) {
                build_sorted_table_range(query, start, i);
                start = i;
            }
            rank = table->rank;
        }
    }

    if (start != i) {
        build_sorted_table_range(query, start, i);
    }
}

static
bool tables_dirty(
    ecs_query_t *query)
{
    if (query->needs_reorder) {
        order_ranked_tables(query->world, query);
    }

    int32_t i, count = ecs_vector_count(query->tables);
    ecs_matched_table_t *tables = ecs_vector_first(query->tables, 
        ecs_matched_table_t);
    bool is_dirty = false;

    for (i = 0; i < count; i ++) {
        ecs_matched_table_t *table_data = &tables[i];
        ecs_table_t *table = table_data->iter_data.table;

        if (!table_data->monitor) {
            table_data->monitor = ecs_table_get_monitor(table);
            is_dirty = true;
        }

        int32_t *dirty_state = ecs_table_get_dirty_state(table);
        int32_t t, type_count = table->column_count;
        for (t = 0; t < type_count + 1; t ++) {
            is_dirty = is_dirty || (dirty_state[t] != table_data->monitor[t]);
        }
    }

    is_dirty = is_dirty || (query->match_count != query->prev_match_count);

    return is_dirty;
}

static
void tables_reset_dirty(
    ecs_query_t *query)
{
    query->prev_match_count = query->match_count;

    int32_t i, count = ecs_vector_count(query->tables);
    ecs_matched_table_t *tables = ecs_vector_first(
        query->tables, ecs_matched_table_t);

    for (i = 0; i < count; i ++) {
        ecs_matched_table_t *table_data = &tables[i];
        ecs_table_t *table = table_data->iter_data.table;

        if (!table_data->monitor) {
            /* If one table doesn't have a monitor, none of the tables will have
             * a monitor, so early out. */
            return;
        }

        int32_t *dirty_state = ecs_table_get_dirty_state(table);
        int32_t t, type_count = table->column_count;
        for (t = 0; t < type_count + 1; t ++) {
            table_data->monitor[t] = dirty_state[t];
        }
    }
}

static
void sort_tables(
    ecs_world_t *world,
    ecs_query_t *query)
{
    ecs_compare_action_t compare = query->compare;
    if (!compare) {
        return;
    }
    
    ecs_entity_t sort_on_component = query->sort_on_component;

    /* Iterate over active tables. Don't bother with inactive tables, since
     * they're empty */
    int32_t i, count = ecs_vector_count(query->tables);
    ecs_matched_table_t *tables = ecs_vector_first(
        query->tables, ecs_matched_table_t);
    bool tables_sorted = false;

    for (i = 0; i < count; i ++) {
        ecs_matched_table_t *table_data = &tables[i];
        ecs_table_t *table = table_data->iter_data.table;

        /* If no monitor had been created for the table yet, create it now */
        bool is_dirty = false;
        if (!table_data->monitor) {
            table_data->monitor = ecs_table_get_monitor(table);

            /* A new table is always dirty */
            is_dirty = true;
        }

        int32_t *dirty_state = ecs_table_get_dirty_state(table);

        is_dirty = is_dirty || (dirty_state[0] != table_data->monitor[0]);

        int32_t index = -1;
        if (sort_on_component) {
            /* Get index of sorted component. We only care if the component we're
            * sorting on has changed or if entities have been added / re(moved) */
            index = ecs_type_index_of(table->type, sort_on_component);
            if (index != -1) {
                ecs_assert(index < ecs_vector_count(table->type), ECS_INTERNAL_ERROR, NULL); 
                is_dirty = is_dirty || (dirty_state[index + 1] != table_data->monitor[index + 1]);
            } else {
                /* Table does not contain component which means the sorted
                 * component is shared. Table does not need to be sorted */
                continue;
            }
        }      
        
        /* Check both if entities have moved (element 0) or if the component
         * we're sorting on has changed (index + 1) */
        if (is_dirty) {
            /* Sort the table */
            sort_table(world, table, index, compare);
            tables_sorted = true;
        }
    }

    if (tables_sorted || query->match_count != query->prev_match_count) {
        build_sorted_tables(query);
        query->match_count ++; /* Increase version if tables changed */
    }
}

static
bool has_refs(
    ecs_query_t *query)
{
    ecs_term_t *terms = query->filter.terms;
    int32_t i, count = query->filter.term_count;

    for (i = 0; i < count; i ++) {
        ecs_term_t *term = &terms[i];
        ecs_term_id_t *subj = &term->args[0];

        if (term->oper == EcsNot && !subj->entity) {
            /* Special case: if oper kind is Not and the query contained a
             * shared expression, the expression is translated to FromEmpty to
             * prevent resolving the ref */
            return true;
        } else if (subj->entity && (subj->entity != EcsThis || subj->set != EcsSelf)) {
            /* If entity is not this, or if it can be substituted by other
             * entities, the query can have references. */
            return true;
        } 
    }

    return false;
}

static
bool has_traits(
    ecs_query_t *query)
{
    ecs_term_t *terms = query->filter.terms;
    int32_t i, count = query->filter.term_count;

    for (i = 0; i < count; i ++) {
        if (is_column_trait(&terms[i])) {
            return true;
        }
    }

    return false;    
}

static
void register_monitors(
    ecs_world_t *world,
    ecs_query_t *query)
{
    ecs_term_t *terms = query->filter.terms;
    int32_t i, count = query->filter.term_count;

    for (i = 0; i < count; i++) {
        ecs_term_t *term = &terms[i];
        ecs_term_id_t *subj = &term->args[0];

        /* If component is requested with CASCADE source register component as a
         * parent monitor. Parent monitors keep track of whether an entity moved
         * in the hierarchy, which potentially requires the query to reorder its
         * tables. 
         * Also register a regular component monitor for EcsCascade columns.
         * This ensures that when the component used in the CASCADE column
         * is added or removed tables are updated accordingly*/
        if (subj->set & EcsSuperSet && subj->set & EcsAll && subj->relation != EcsIsA) {
            if (term->oper != EcsOr) {
                if (term->args[0].relation != EcsIsA) {
                    ecs_monitor_register(
                        world, term->args[0].relation, term->id, query);
                }
                ecs_monitor_register(world, 0, term->id, query);
            }

        /* FromAny also requires registering a monitor, as FromAny columns can
         * be matched with prefabs. The only term kinds that do not require
         * registering a monitor are FromOwned and FromEmpty. */
        } else if ((subj->set & EcsSuperSet) || (subj->entity != EcsThis)) {
            if (term->oper != EcsOr) {
                ecs_monitor_register(world, 0, term->id, query);
            }
        }
    };
}

static
void process_signature(
    ecs_world_t *world,
    ecs_query_t *query)
{
    ecs_term_t *terms = query->filter.terms;
    int32_t i, count = query->filter.term_count;

    for (i = 0; i < count; i ++) {
        ecs_term_t *term = &terms[i];
        ecs_term_id_t *pred = &term->pred;
        ecs_term_id_t *subj = &term->args[0];
        ecs_term_id_t *obj = &term->args[1];
        ecs_oper_kind_t op = term->oper; 
        ecs_inout_kind_t inout = term->inout;

        (void)pred;
        (void)obj;

        /* Queries do not support variables */
        ecs_assert(pred->var_kind != EcsVarIsVariable, 
            ECS_UNSUPPORTED, NULL);
        ecs_assert(subj->var_kind != EcsVarIsVariable, 
            ECS_UNSUPPORTED, NULL);
        ecs_assert(obj->var_kind != EcsVarIsVariable, 
            ECS_UNSUPPORTED, NULL);

        /* Queries do not support subset substitutions */
        ecs_assert(!(pred->set & EcsSubSet), ECS_UNSUPPORTED, NULL);
        ecs_assert(!(subj->set & EcsSubSet), ECS_UNSUPPORTED, NULL);
        ecs_assert(!(obj->set & EcsSubSet), ECS_UNSUPPORTED, NULL);

        /* Superset/subset substitutions aren't supported for pred/obj */
        ecs_assert(pred->set == EcsDefaultSet, ECS_UNSUPPORTED, NULL);
        ecs_assert(obj->set == EcsDefaultSet, ECS_UNSUPPORTED, NULL);

        if (subj->set == EcsDefaultSet) {
            subj->set = EcsSelf;
        }

        /* If self is not included in set, always start from depth 1 */
        if (!subj->min_depth && !(subj->set & EcsSelf)) {
            subj->min_depth = 1;
        }

        if (inout != EcsIn) {
            query->flags |= EcsQueryHasOutColumns;
        }

        if (op == EcsOptional) {
            query->flags |= EcsQueryHasOptional;
        }

        if (!(query->flags & EcsQueryMatchDisabled)) {
            if (op == EcsAnd || op == EcsOr || op == EcsOptional) {
                if (term->id == EcsDisabled) {
                    query->flags |= EcsQueryMatchDisabled;
                }
            }
        }

        if (!(query->flags & EcsQueryMatchPrefab)) {
            if (op == EcsAnd || op == EcsOr || op == EcsOptional) {
                if (term->id == EcsPrefab) {
                    query->flags |= EcsQueryMatchPrefab;
                }
            }
        }

        if (subj->entity == EcsThis) {
            query->flags |= EcsQueryNeedsTables;
        }

        if (subj->set & EcsAll && term->oper == EcsOptional) {
            query->cascade_by = i + 1;
            query->rank_on_component = term->id;
        }

        if (subj->entity && subj->entity != EcsThis && subj->set == EcsSelf) {
            ecs_set_watch(world, term->args[0].entity);
        }
    }

    query->flags |= (ecs_flags32_t)(has_refs(query) * EcsQueryHasRefs);
    query->flags |= (ecs_flags32_t)(has_traits(query) * EcsQueryHasTraits);

    if (!(query->flags & EcsQueryIsSubquery)) {
        register_monitors(world, query);
    }
}

static
bool match_table(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_table_t *table)
{
    if (ecs_query_match(world, table, query, NULL)) {
        add_table(world, query, table);
        return true;
    }
    return false;
}

/* Move table from empty to non-empty list, or vice versa */
static
int32_t move_table(
    ecs_query_t *query,
    ecs_table_t *table,
    int32_t index,
    ecs_vector_t **dst_array,
    ecs_vector_t *src_array,
    bool activate)
{
    (void)table;

    int32_t new_index = 0;
    int32_t last_src_index = ecs_vector_count(src_array) - 1;
    ecs_assert(last_src_index >= 0, ECS_INTERNAL_ERROR, NULL);

    ecs_matched_table_t *mt = ecs_vector_last(src_array, ecs_matched_table_t);
    
    /* The last table of the source array will be moved to the location of the
     * table to move, do some bookkeeping to keep things consistent. */
    if (last_src_index) {
        ecs_table_indices_t *ti = ecs_map_get(query->table_indices, 
            ecs_table_indices_t, mt->iter_data.table->id);

        int i, count = ti->count;
        for (i = 0; i < count; i ++) {
            int32_t old_index = ti->indices[i];
            if (activate) {
                if (old_index >= 0) {
                    /* old_index should be negative if activate is true, since
                     * we're moving from the empty list to the non-empty list. 
                     * However, if the last table in the source array is also
                     * the table being moved, this can happen. */
                    ecs_assert(table == mt->iter_data.table, 
                        ECS_INTERNAL_ERROR, NULL);
                    continue;
                }
                /* If activate is true, src = the empty list, and index should
                 * be negative. */
                old_index = old_index * -1 - 1; /* Normalize */
            }

            /* Ensure to update correct index, as there can be more than one */
            if (old_index == last_src_index) {
                if (activate) {
                    ti->indices[i] = index * -1 - 1;
                } else {
                    ti->indices[i] = index;
                }
                break;
            }
        }

        /* If the src array contains tables, there must be a table that will get
         * moved. */
        ecs_assert(i != count, ECS_INTERNAL_ERROR, NULL);
    } else {
        /* If last_src_index is 0, the table to move was the only table in the
         * src array, so no other administration needs to be updated. */
    }

    /* Actually move the table. Only move from src to dst if we have a
     * dst_array, otherwise just remove it from src. */
    if (dst_array) {
        new_index = ecs_vector_count(*dst_array);
        ecs_vector_move_index(dst_array, src_array, ecs_matched_table_t, index);

        /* Make sure table is where we expect it */
        mt = ecs_vector_last(*dst_array, ecs_matched_table_t);
        ecs_assert(mt->iter_data.table == table, ECS_INTERNAL_ERROR, NULL);
        ecs_assert(ecs_vector_count(*dst_array) == (new_index + 1), 
            ECS_INTERNAL_ERROR, NULL);  
    } else {
        ecs_vector_remove_index(src_array, ecs_matched_table_t, index);
    }

    /* Ensure that src array has now one element less */
    ecs_assert(ecs_vector_count(src_array) == last_src_index, 
        ECS_INTERNAL_ERROR, NULL);

    /* Return new index for table */
    if (activate) {
        /* Table is now active, index is positive */
        return new_index;
    } else {
        /* Table is now inactive, index is negative */
        return new_index * -1 - 1;
    }
}

/** Table activation happens when a table was or becomes empty. Deactivated
 * tables are not considered by the system in the main loop. */
static
void activate_table(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_table_t *table,
    bool active)
{    
    ecs_vector_t *src_array, *dst_array;
    int32_t activated = 0;
    int32_t prev_dst_count = 0;
    (void)world;
    (void)prev_dst_count; /* Only used when built with systems module */

    if (active) {
        src_array = query->empty_tables;
        dst_array = query->tables;
        prev_dst_count = ecs_vector_count(dst_array);
    } else {
        src_array = query->tables;
        dst_array = query->empty_tables;
    }

    ecs_table_indices_t *ti = ecs_map_get(
        query->table_indices, ecs_table_indices_t, table->id);

    if (ti) {
        int32_t i, count = ti->count;
        for (i = 0; i < count; i ++) {
            int32_t index = ti->indices[i];

            if (index < 0) {
                if (!active) {
                    /* If table is already inactive, no need to move */
                    continue;
                }
                index = index * -1 - 1;
            } else {
                if (active) {
                    /* If table is already active, no need to move */
                    continue;
                }
            }

            ecs_matched_table_t *mt = ecs_vector_get(
                src_array, ecs_matched_table_t, index);
            ecs_assert(mt->iter_data.table == table, ECS_INTERNAL_ERROR, NULL);
            (void)mt;
            
            activated ++;

            ti->indices[i] = move_table(
                query, table, index, &dst_array, src_array, active);
        }

        if (activated) {
            /* Activate system if registered with query */
#ifdef FLECS_SYSTEMS_H
            if (query->system) {
                int32_t dst_count = ecs_vector_count(dst_array);
                if (active) {
                    if (!prev_dst_count && dst_count) {
                        ecs_system_activate(world, query->system, true, NULL);
                    }
                } else if (ecs_vector_count(src_array) == 0) {
                    ecs_system_activate(world, query->system, false, NULL);
                }
            }
#endif
        }

        if (active)  {
            query->tables = dst_array;
        } else {
            query->empty_tables = dst_array;
        }
    }
    
    if (!activated) {
        /* Received an activate event for a table we're not matched with. This
         * can only happen if this is a subquery */
        ecs_assert((query->flags & EcsQueryIsSubquery) != 0, 
            ECS_INTERNAL_ERROR, NULL);
        return;
    }

    /* Signal query it needs to reorder tables. Doing this in place could slow
     * down scenario's where a large number of tables is matched with an ordered
     * query. Since each table would trigger the activate signal, there would be
     * as many sorts as added tables, vs. only one when ordering happens when an
     * iterator is obtained. */
    query->needs_reorder = true;
}

static
void add_subquery(
    ecs_world_t *world, 
    ecs_query_t *parent, 
    ecs_query_t *subquery) 
{
    ecs_query_t **elem = ecs_vector_add(&parent->subqueries, ecs_query_t*);
    *elem = subquery;

    /* Iterate matched tables, match them with subquery */
    ecs_matched_table_t *tables = ecs_vector_first(parent->tables, ecs_matched_table_t);
    int32_t i, count = ecs_vector_count(parent->tables);

    for (i = 0; i < count; i ++) {
        ecs_matched_table_t *table = &tables[i];
        match_table(world, subquery, table->iter_data.table);
        activate_table(world, subquery, table->iter_data.table, true);
    }

    /* Do the same for inactive tables */
    tables = ecs_vector_first(parent->empty_tables, ecs_matched_table_t);
    count = ecs_vector_count(parent->empty_tables);

    for (i = 0; i < count; i ++) {
        ecs_matched_table_t *table = &tables[i];
        match_table(world, subquery, table->iter_data.table);
    }    
}

static
void notify_subqueries(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_query_event_t *event)
{
    if (query->subqueries) {
        ecs_query_t **queries = ecs_vector_first(query->subqueries, ecs_query_t*);
        int32_t i, count = ecs_vector_count(query->subqueries);

        ecs_query_event_t sub_event = *event;
        sub_event.parent_query = query;

        for (i = 0; i < count; i ++) {
            ecs_query_t *sub = queries[i];
            ecs_query_notify(world, sub, &sub_event);
        }
    }
}

static
void free_matched_table(
    ecs_matched_table_t *table)
{
    ecs_os_free(table->iter_data.columns);
    ecs_os_free(table->iter_data.components);
    ecs_os_free((ecs_vector_t**)table->iter_data.types);
    ecs_os_free(table->iter_data.references);
    ecs_os_free(table->sparse_columns);
    ecs_os_free(table->bitset_columns);
    ecs_os_free(table->monitor);
}

/** Check if a table was matched with the system */
static
ecs_table_indices_t* get_table_indices(
    ecs_query_t *query,
    ecs_table_t *table)
{
    return ecs_map_get(query->table_indices, ecs_table_indices_t, table->id);
}

static
void resolve_cascade_container(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_table_indices_t *ti,
    ecs_type_t table_type)
{
    int32_t i, count = ti->count;
    for (i = 0; i < count; i ++) {
        int32_t table_data_index = ti->indices[i];
        ecs_matched_table_t *table_data;

        if (table_data_index >= 0) {
            table_data = ecs_vector_get(
                query->tables, ecs_matched_table_t, table_data_index);            
        } else {
            table_data = ecs_vector_get(
                query->empty_tables, ecs_matched_table_t, 
                    -1 * table_data_index - 1);
        }
        
        ecs_assert(table_data->iter_data.references != 0, ECS_INTERNAL_ERROR, NULL);

        /* Obtain reference index */
        int32_t *column_indices = table_data->iter_data.columns;
        int32_t column = query->cascade_by - 1;
        int32_t ref_index = -column_indices[column] - 1;

        /* Obtain pointer to the reference data */
        ecs_ref_t *references = table_data->iter_data.references;
        ecs_ref_t *ref = &references[ref_index];
        ecs_assert(ref->component == get_cascade_component(query), 
            ECS_INTERNAL_ERROR, NULL);

        /* Resolve container entity */
        ecs_entity_t container = ecs_find_in_type(
            world, table_type, ref->component, EcsChildOf);

        /* If container was found, update the reference */
        if (container) {
            references[ref_index].entity = container;
            ecs_get_ref_w_id(
                world, &references[ref_index], container, 
                ref->component);
        } else {
            references[ref_index].entity = 0;
        }
    }
}

/* Remove table */
static
void remove_table(
    ecs_query_t *query,
    ecs_table_t *table,
    ecs_vector_t *tables,
    int32_t index,
    bool empty)
{
    ecs_matched_table_t *mt = ecs_vector_get(
        tables, ecs_matched_table_t, index);
    if (!mt) {
        /* Query was notified of a table it doesn't match with, this can only
         * happen if query is a subquery. */
        ecs_assert(query->flags & EcsQueryIsSubquery, ECS_INTERNAL_ERROR, NULL);
        return;
    }
    
    ecs_assert(mt->iter_data.table == table, ECS_INTERNAL_ERROR, NULL);
    (void)table;

    /* Free table before moving, as the move will cause another table to occupy
     * the memory of mt */
    free_matched_table(mt);  
    move_table(query, mt->iter_data.table, index, NULL, tables, empty);
}

static
void unmatch_table(
    ecs_query_t *query,
    ecs_table_t *table,
    ecs_table_indices_t *ti)
{
    if (!ti) {
        ti = get_table_indices(query, table);
        if (!ti) {
            return;
        }
    }

    int32_t i, count = ti->count;
    for (i = 0; i < count; i ++) {
        int32_t index = ti->indices[i];
        if (index < 0) {
            index = index * -1 - 1;
            remove_table(query, table, query->empty_tables, index, true);
        } else {
            remove_table(query, table, query->tables, index, false);
        }
    }

    ecs_os_free(ti->indices);
    ecs_map_remove(query->table_indices, table->id);
}

static
void rematch_table(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_table_t *table)
{
    ecs_table_indices_t *match = get_table_indices(query, table);

    if (ecs_query_match(world, table, query, NULL)) {
        /* If the table matches, and it is not currently matched, add */
        if (match == NULL) {
            add_table(world, query, table);

        /* If table still matches and has cascade column, reevaluate the
         * sources of references. This may have changed in case 
         * components were added/removed to container entities */ 
        } else if (query->cascade_by) {
            resolve_cascade_container(
                world, query, match, table->type);

        /* If query has optional columns, it is possible that a column that
         * previously had data no longer has data, or vice versa. Do a full
         * rematch to make sure data is consistent. */
        } else if (query->flags & EcsQueryHasOptional) {
            unmatch_table(query, table, match);
            if (!(query->flags & EcsQueryIsSubquery)) {
                ecs_table_notify(world, table, &(ecs_table_event_t){
                    .kind = EcsTableQueryUnmatch,
                    .query = query
                }); 
            }
            add_table(world, query, table);
        }
    } else {
        /* Table no longer matches, remove */
        if (match != NULL) {
            unmatch_table(query, table, match);
            if (!(query->flags & EcsQueryIsSubquery)) {
                ecs_table_notify(world, table, &(ecs_table_event_t){
                    .kind = EcsTableQueryUnmatch,
                    .query = query
                });
            }
            notify_subqueries(world, query, &(ecs_query_event_t){
                .kind = EcsQueryTableUnmatch,
                .table = table
            });
        }
    }
}

/* Rematch system with tables after a change happened to a watched entity */
static
void rematch_tables(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_query_t *parent_query)
{
    if (parent_query) {
        ecs_matched_table_t *tables = ecs_vector_first(parent_query->tables, ecs_matched_table_t);
        int32_t i, count = ecs_vector_count(parent_query->tables);
        for (i = 0; i < count; i ++) {
            ecs_table_t *table = tables[i].iter_data.table;
            rematch_table(world, query, table);
        }

        tables = ecs_vector_first(parent_query->empty_tables, ecs_matched_table_t);
        count = ecs_vector_count(parent_query->empty_tables);
        for (i = 0; i < count; i ++) {
            ecs_table_t *table = tables[i].iter_data.table;
            rematch_table(world, query, table);
        }        
    } else {
        ecs_sparse_t *tables = world->store.tables;
        int32_t i, count = ecs_sparse_count(tables);

        for (i = 0; i < count; i ++) {
            /* Is the system currently matched with the table? */
            ecs_table_t *table = ecs_sparse_get(tables, ecs_table_t, i);
            rematch_table(world, query, table);
        }
    }

    group_tables(world, query);
    order_ranked_tables(world, query);

    /* Enable/disable system if constraints are (not) met. If the system is
     * already dis/enabled this operation has no side effects. */
    query->constraints_satisfied = ecs_filter_match_entity(
        world, &query->filter, 0);      
}

static
void remove_subquery(
    ecs_query_t *parent, 
    ecs_query_t *sub)
{
    ecs_assert(parent != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(sub != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(parent->subqueries != NULL, ECS_INTERNAL_ERROR, NULL);

    int32_t i, count = ecs_vector_count(parent->subqueries);
    ecs_query_t **sq = ecs_vector_first(parent->subqueries, ecs_query_t*);

    for (i = 0; i < count; i ++) {
        if (sq[i] == sub) {
            break;
        }
    }

    ecs_vector_remove_index(parent->subqueries, ecs_query_t*, i);
}

/* -- Private API -- */

void ecs_query_notify(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_query_event_t *event)
{
    bool notify = true;

    switch(event->kind) {
    case EcsQueryTableMatch:
        /* Creation of new table */
        if (match_table(world, query, event->table)) {
            if (query->subqueries) {
                notify_subqueries(world, query, event);
            }
        }
        notify = false;
        break;
    case EcsQueryTableUnmatch:
        /* Deletion of table */
        unmatch_table(query, event->table, NULL);
        break;
    case EcsQueryTableRematch:
        /* Rematch tables of query */
        rematch_tables(world, query, event->parent_query);
        break;        
    case EcsQueryTableEmpty:
        /* Table is empty, deactivate */
        activate_table(world, query, event->table, false);
        break;
    case EcsQueryTableNonEmpty:
        /* Table is non-empty, activate */
        activate_table(world, query, event->table, true);
        break;
    case EcsQueryOrphan:
        ecs_assert(query->flags & EcsQueryIsSubquery, ECS_INTERNAL_ERROR, NULL);
        query->flags |= EcsQueryIsOrphaned;
        query->parent = NULL;
        break;
    }

    if (notify) {
        notify_subqueries(world, query, event);
    }
}


/* -- Public API -- */

ecs_query_t* ecs_query_init(
    ecs_world_t *world,
    const ecs_query_desc_t *desc)
{
    ecs_filter_t f;
    if (ecs_filter_init(world, &f, &desc->filter)) {
        return NULL;
    }

    ecs_query_t *result = ecs_sparse_add(world->queries, ecs_query_t);
    result->world = world;
    result->filter = f;
    result->table_indices = ecs_map_new(ecs_table_indices_t, 0);
    result->tables = ecs_vector_new(ecs_matched_table_t, 0);
    result->empty_tables = ecs_vector_new(ecs_matched_table_t, 0);
    result->system = desc->system;
    result->prev_match_count = -1;
    result->id = ecs_sparse_last_id(world->queries);

    if (desc->parent != NULL) {
        result->flags |= EcsQueryIsSubquery;
    }

    process_signature(world, result);

    ecs_trace_2("query #[green]%s#[reset] created with expression #[red]%s", 
        query_name(world, result), result->filter.expr);

    ecs_log_push();

    if (!desc->parent) {
        if (result->flags & EcsQueryNeedsTables) {
            if (desc->system) {
                if (ecs_has_id(world, desc->system, EcsMonitor)) {
                    result->flags |= EcsQueryMonitor;
                }
                
                if (ecs_has_id(world, desc->system, EcsOnSet)) {
                    result->flags |= EcsQueryOnSet;
                }

                if (ecs_has_id(world, desc->system, EcsUnSet)) {
                    result->flags |= EcsQueryUnSet;
                }  
            }      

            match_tables(world, result);
        } else {
            /* Add stub table that resolves references (if any) so everything is
             * preprocessed when the query is evaluated. */
            add_table(world, result, NULL);
        }
    } else {
        add_subquery(world, desc->parent, result);
        result->parent = desc->parent;
    }

    result->constraints_satisfied = ecs_filter_match_entity(
        world, &result->filter, 0);

    if (result->cascade_by) {
        result->group_table = rank_by_depth;
    }

    /* If a system is specified, ensure that if there are any subjects in the
     * filter that refer to the system, the component is added */
    if (desc->system)  {
        int32_t t, term_count = result->filter.term_count;
        ecs_term_t *terms = result->filter.terms;

        for (t = 0; t < term_count; t ++) {
            ecs_term_t *term = &terms[t];
            if (term->args[0].entity == desc->system) {
                ecs_add_id(world, desc->system, term->id);
            }
        }        
    }

    if (desc->order_by) {
        ecs_query_order_by(world, result, desc->order_by_id, desc->order_by);
    }

    if (desc->group_by) {
        ecs_query_group_by(world, result, desc->group_by_id, desc->group_by);
    }

    ecs_log_pop();

    return result;
}

void ecs_query_fini(
    ecs_query_t *query)
{
    ecs_world_t *world = query->world;
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);

    if ((query->flags & EcsQueryIsSubquery) &&
        !(query->flags & EcsQueryIsOrphaned))
    {
        remove_subquery(query->parent, query);
    }

    notify_subqueries(world, query, &(ecs_query_event_t){
        .kind = EcsQueryOrphan
    });

    ecs_vector_each(query->empty_tables, ecs_matched_table_t, table, {
        if (!(query->flags & EcsQueryIsSubquery)) {
            ecs_table_notify(world, table->iter_data.table, &(ecs_table_event_t){
                .kind = EcsTableQueryUnmatch,
                .query = query
            });
        }    
        free_matched_table(table);
    });

    ecs_vector_each(query->tables, ecs_matched_table_t, table, {
        if (!(query->flags & EcsQueryIsSubquery)) {
            ecs_table_notify(world, table->iter_data.table, &(ecs_table_event_t){
                .kind = EcsTableQueryUnmatch,
                .query = query
            });
        }
        free_matched_table(table);
    });

    ecs_map_iter_t it = ecs_map_iter(query->table_indices);
    ecs_table_indices_t *ti;
    while ((ti = ecs_map_next(&it, ecs_table_indices_t, NULL))) {
        ecs_os_free(ti->indices);
    }

    ecs_map_free(query->table_indices);
    ecs_vector_free(query->subqueries);
    ecs_vector_free(query->tables);
    ecs_vector_free(query->empty_tables);
    ecs_vector_free(query->table_slices);
    ecs_filter_fini(&query->filter);
    
    /* Remove query from storage */
    ecs_sparse_remove(world->queries, query->id);
}

ecs_filter_t* ecs_query_get_filter(
    ecs_query_t *query)
{
    return &query->filter;
}

/* Create query iterator */
ecs_iter_t ecs_query_iter_page(
    ecs_query_t *query,
    int32_t offset,
    int32_t limit)
{
    ecs_assert(query != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!(query->flags & EcsQueryIsOrphaned), ECS_INVALID_PARAMETER, NULL);

    ecs_world_t *world = query->world;

    if (query->needs_reorder) {
        order_ranked_tables(world, query);
    }
    
    sort_tables(world, query);

    if (!world->is_readonly && query->flags & EcsQueryHasRefs) {
        ecs_eval_component_monitors(world);
    }

    tables_reset_dirty(query);

    int32_t table_count;
    if (query->table_slices) {
        table_count = ecs_vector_count(query->table_slices);
    } else {
        table_count = ecs_vector_count(query->tables);
    }

    ecs_query_iter_t it = {
        .page_iter = {
            .offset = offset,
            .limit = limit,
            .remaining = limit
        },
        .index = 0,
    };

    return (ecs_iter_t){
        .world = world,
        .query = query,
        .column_count = query->filter.term_count_actual,
        .table_count = table_count,
        .inactive_table_count = ecs_vector_count(query->empty_tables),
        .iter.query = it
    };
}

ecs_iter_t ecs_query_iter(
    ecs_query_t *query)
{
    return ecs_query_iter_page(query, 0, 0);
}

void ecs_query_set_iter(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_iter_t *it,
    int32_t table_index,
    int32_t row,
    int32_t count)
{
    (void)world;
    
    ecs_assert(query != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!(query->flags & EcsQueryIsOrphaned), ECS_INVALID_PARAMETER, NULL);
    
    ecs_matched_table_t *table_data = ecs_vector_get(
        query->tables, ecs_matched_table_t, table_index);
    ecs_assert(table_data != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_table_t *table = table_data->iter_data.table;
    ecs_data_t *data = ecs_table_get_data(table);
    ecs_assert(data != NULL, ECS_INTERNAL_ERROR, NULL);
    
    ecs_entity_t *entity_buffer = ecs_vector_first(data->entities, ecs_entity_t);  
    it->entities = &entity_buffer[row];

    it->world = NULL;
    it->query = query;
    it->column_count = query->filter.term_count_actual;
    it->table_count = 1;
    it->inactive_table_count = 0;
    it->table_columns = data->columns;
    it->table = &table_data->iter_data;
    it->offset = row;
    it->count = count;
    it->total_count = count;
}

static
int ecs_page_iter_next(
    ecs_page_iter_t *it,
    ecs_page_cursor_t *cur)
{
    int32_t offset = it->offset;
    int32_t limit = it->limit;
    if (!(offset || limit)) {
        return cur->count == 0;
    }

    int32_t count = cur->count;
    int32_t remaining = it->remaining;

    if (offset) {
        if (offset > count) {
            /* No entities to iterate in current table */
            it->offset -= count;
            return 1;
        } else {
            cur->first += offset;
            count = cur->count -= offset;
            it->offset = 0;
        }
    }

    if (remaining) {
        if (remaining > count) {
            it->remaining -= count;
        } else {
            count = cur->count = remaining;
            it->remaining = 0;
        }
    } else if (limit) {
        /* Limit hit: no more entities left to iterate */
        return -1;
    }

    return count == 0;
}

static
int find_smallest_column(
    ecs_table_t *table,
    ecs_matched_table_t *table_data,
    ecs_vector_t *sparse_columns)
{
    ecs_sparse_column_t *sparse_column_array = 
        ecs_vector_first(sparse_columns, ecs_sparse_column_t);
    int32_t i, count = ecs_vector_count(sparse_columns);
    int32_t min = INT_MAX, index = 0;

    for (i = 0; i < count; i ++) {
        /* The array with sparse queries for the matched table */
        ecs_sparse_column_t *sparse_column = &sparse_column_array[i];

        /* Pointer to the switch column struct of the table */
        ecs_sw_column_t *sc = sparse_column->sw_column;

        /* If the sparse column pointer hadn't been retrieved yet, do it now */
        if (!sc) {
            /* Get the table column index from the signature column index */
            int32_t table_column_index = table_data->iter_data.columns[
                sparse_column->signature_column_index];

            /* Translate the table column index to switch column index */
            table_column_index -= table->sw_column_offset;
            ecs_assert(table_column_index >= 1, ECS_INTERNAL_ERROR, NULL);

            /* Get the sparse column */
            ecs_data_t *data = ecs_table_get_data(table);
            sc = sparse_column->sw_column = 
                &data->sw_columns[table_column_index - 1];
        }

        /* Find the smallest column */
        ecs_switch_t *sw = sc->data;
        int32_t case_count = ecs_switch_case_count(sw, sparse_column->sw_case);
        if (case_count < min) {
            min = case_count;
            index = i + 1;
        }
    }

    return index;
}

static
int sparse_column_next(
    ecs_table_t *table,
    ecs_matched_table_t *matched_table,
    ecs_vector_t *sparse_columns,
    ecs_query_iter_t *iter,
    ecs_page_cursor_t *cur)
{
    bool first_iteration = false;
    int32_t sparse_smallest;

    if (!(sparse_smallest = iter->sparse_smallest)) {
        sparse_smallest = iter->sparse_smallest = find_smallest_column(
            table, matched_table, sparse_columns);
        first_iteration = true;
    }

    sparse_smallest -= 1;

    ecs_sparse_column_t *columns = ecs_vector_first(
        sparse_columns, ecs_sparse_column_t);
    ecs_sparse_column_t *column = &columns[sparse_smallest];
    ecs_switch_t *sw, *sw_smallest = column->sw_column->data;
    ecs_entity_t case_smallest = column->sw_case;

    /* Find next entity to iterate in sparse column */
    int32_t first;
    if (first_iteration) {
        first = ecs_switch_first(sw_smallest, case_smallest);
    } else {
        first = ecs_switch_next(sw_smallest, iter->sparse_first);
    }

    if (first == -1) {
        goto done;
    }    

    /* Check if entity matches with other sparse columns, if any */
    int32_t i, count = ecs_vector_count(sparse_columns);
    do {
        for (i = 0; i < count; i ++) {
            if (i == sparse_smallest) {
                /* Already validated this one */
                continue;
            }

            column = &columns[i];
            sw = column->sw_column->data;

            if (ecs_switch_get(sw, first) != column->sw_case) {
                first = ecs_switch_next(sw_smallest, first);
                if (first == -1) {
                    goto done;
                }
            }
        }
    } while (i != count);

    cur->first = iter->sparse_first = first;
    cur->count = 1;

    return 0;
done:
    /* Iterated all elements in the sparse list, we should move to the
     * next matched table. */
    iter->sparse_smallest = 0;
    iter->sparse_first = 0;

    return -1;
}

#define BS_MAX ((uint64_t)0xFFFFFFFFFFFFFFFF)

static
int bitset_column_next(
    ecs_table_t *table,
    ecs_vector_t *bitset_columns,
    ecs_query_iter_t *iter,
    ecs_page_cursor_t *cur)
{
    /* Precomputed single-bit test */
    static const uint64_t bitmask[64] = {
    (uint64_t)1 << 0, (uint64_t)1 << 1, (uint64_t)1 << 2, (uint64_t)1 << 3,
    (uint64_t)1 << 4, (uint64_t)1 << 5, (uint64_t)1 << 6, (uint64_t)1 << 7,
    (uint64_t)1 << 8, (uint64_t)1 << 9, (uint64_t)1 << 10, (uint64_t)1 << 11,
    (uint64_t)1 << 12, (uint64_t)1 << 13, (uint64_t)1 << 14, (uint64_t)1 << 15,
    (uint64_t)1 << 16, (uint64_t)1 << 17, (uint64_t)1 << 18, (uint64_t)1 << 19,
    (uint64_t)1 << 20, (uint64_t)1 << 21, (uint64_t)1 << 22, (uint64_t)1 << 23,
    (uint64_t)1 << 24, (uint64_t)1 << 25, (uint64_t)1 << 26, (uint64_t)1 << 27,  
    (uint64_t)1 << 28, (uint64_t)1 << 29, (uint64_t)1 << 30, (uint64_t)1 << 31,
    (uint64_t)1 << 32, (uint64_t)1 << 33, (uint64_t)1 << 34, (uint64_t)1 << 35,  
    (uint64_t)1 << 36, (uint64_t)1 << 37, (uint64_t)1 << 38, (uint64_t)1 << 39,
    (uint64_t)1 << 40, (uint64_t)1 << 41, (uint64_t)1 << 42, (uint64_t)1 << 43,
    (uint64_t)1 << 44, (uint64_t)1 << 45, (uint64_t)1 << 46, (uint64_t)1 << 47,  
    (uint64_t)1 << 48, (uint64_t)1 << 49, (uint64_t)1 << 50, (uint64_t)1 << 51,
    (uint64_t)1 << 52, (uint64_t)1 << 53, (uint64_t)1 << 54, (uint64_t)1 << 55,  
    (uint64_t)1 << 56, (uint64_t)1 << 57, (uint64_t)1 << 58, (uint64_t)1 << 59,
    (uint64_t)1 << 60, (uint64_t)1 << 61, (uint64_t)1 << 62, (uint64_t)1 << 63
    };

    /* Precomputed test to verify if remainder of block is set (or not) */
    static const uint64_t bitmask_remain[64] = {
    BS_MAX, BS_MAX - (BS_MAX >> 63), BS_MAX - (BS_MAX >> 62),
    BS_MAX - (BS_MAX >> 61), BS_MAX - (BS_MAX >> 60), BS_MAX - (BS_MAX >> 59),
    BS_MAX - (BS_MAX >> 58), BS_MAX - (BS_MAX >> 57), BS_MAX - (BS_MAX >> 56), 
    BS_MAX - (BS_MAX >> 55), BS_MAX - (BS_MAX >> 54), BS_MAX - (BS_MAX >> 53), 
    BS_MAX - (BS_MAX >> 52), BS_MAX - (BS_MAX >> 51), BS_MAX - (BS_MAX >> 50), 
    BS_MAX - (BS_MAX >> 49), BS_MAX - (BS_MAX >> 48), BS_MAX - (BS_MAX >> 47), 
    BS_MAX - (BS_MAX >> 46), BS_MAX - (BS_MAX >> 45), BS_MAX - (BS_MAX >> 44), 
    BS_MAX - (BS_MAX >> 43), BS_MAX - (BS_MAX >> 42), BS_MAX - (BS_MAX >> 41), 
    BS_MAX - (BS_MAX >> 40), BS_MAX - (BS_MAX >> 39), BS_MAX - (BS_MAX >> 38), 
    BS_MAX - (BS_MAX >> 37), BS_MAX - (BS_MAX >> 36), BS_MAX - (BS_MAX >> 35), 
    BS_MAX - (BS_MAX >> 34), BS_MAX - (BS_MAX >> 33), BS_MAX - (BS_MAX >> 32), 
    BS_MAX - (BS_MAX >> 31), BS_MAX - (BS_MAX >> 30), BS_MAX - (BS_MAX >> 29), 
    BS_MAX - (BS_MAX >> 28), BS_MAX - (BS_MAX >> 27), BS_MAX - (BS_MAX >> 26), 
    BS_MAX - (BS_MAX >> 25), BS_MAX - (BS_MAX >> 24), BS_MAX - (BS_MAX >> 23), 
    BS_MAX - (BS_MAX >> 22), BS_MAX - (BS_MAX >> 21), BS_MAX - (BS_MAX >> 20), 
    BS_MAX - (BS_MAX >> 19), BS_MAX - (BS_MAX >> 18), BS_MAX - (BS_MAX >> 17), 
    BS_MAX - (BS_MAX >> 16), BS_MAX - (BS_MAX >> 15), BS_MAX - (BS_MAX >> 14), 
    BS_MAX - (BS_MAX >> 13), BS_MAX - (BS_MAX >> 12), BS_MAX - (BS_MAX >> 11), 
    BS_MAX - (BS_MAX >> 10), BS_MAX - (BS_MAX >> 9), BS_MAX - (BS_MAX >> 8), 
    BS_MAX - (BS_MAX >> 7), BS_MAX - (BS_MAX >> 6), BS_MAX - (BS_MAX >> 5), 
    BS_MAX - (BS_MAX >> 4), BS_MAX - (BS_MAX >> 3), BS_MAX - (BS_MAX >> 2),
    BS_MAX - (BS_MAX >> 1)
    };

    int32_t i, count = ecs_vector_count(bitset_columns);
    ecs_bitset_column_t *columns = ecs_vector_first(
        bitset_columns, ecs_bitset_column_t);
    int32_t bs_offset = table->bs_column_offset;

    int32_t first = iter->bitset_first;
    int32_t last = 0;

    for (i = 0; i < count; i ++) {
        ecs_bitset_column_t *column = &columns[i];
        ecs_bs_column_t *bs_column = columns[i].bs_column;

        if (!bs_column) {
            ecs_data_t *data = table->data;
            int32_t index = column->column_index;
            ecs_assert((index - bs_offset >= 0), ECS_INTERNAL_ERROR, NULL);
            bs_column = &data->bs_columns[index - bs_offset];
            columns[i].bs_column = bs_column;
        }
        
        ecs_bitset_t *bs = &bs_column->data;
        int32_t bs_elem_count = bs->count;
        int32_t bs_block = first >> 6;
        int32_t bs_block_count = ((bs_elem_count - 1) >> 6) + 1;

        if (bs_block >= bs_block_count) {
            goto done;
        }

        uint64_t *data = bs->data;
        int32_t bs_start = first & 0x3F;

        /* Step 1: find the first non-empty block */
        uint64_t v = data[bs_block];
        uint64_t remain = bitmask_remain[bs_start];
        while (!(v & remain)) {
            /* If no elements are remaining, move to next block */
            if ((++bs_block) >= bs_block_count) {
                /* No non-empty blocks left */
                goto done;
            }

            bs_start = 0;
            remain = BS_MAX; /* Test the full block */
            v = data[bs_block];
        }

        /* Step 2: find the first non-empty element in the block */
        while (!(v & bitmask[bs_start])) {
            bs_start ++;

            /* Block was not empty, so bs_start must be smaller than 64 */
            ecs_assert(bs_start < 64, ECS_INTERNAL_ERROR, NULL);
        }
        
        /* Step 3: Find number of contiguous enabled elements after start */
        int32_t bs_end = bs_start, bs_block_end = bs_block;
        
        remain = bitmask_remain[bs_end];
        while ((v & remain) == remain) {
            bs_end = 0;
            bs_block_end ++;

            if (bs_block_end == bs_block_count) {
                break;
            }

            v = data[bs_block_end];
            remain = BS_MAX; /* Test the full block */
        }

        /* Step 4: find remainder of enabled elements in current block */
        if (bs_block_end != bs_block_count) {
            while ((v & bitmask[bs_end])) {
                bs_end ++;
            }
        }

        /* Block was not 100% occupied, so bs_start must be smaller than 64 */
        ecs_assert(bs_end < 64, ECS_INTERNAL_ERROR, NULL);

        /* Step 5: translate to element start/end and make sure that each column
         * range is a subset of the previous one. */
        first = bs_block * 64 + bs_start;
        int32_t cur_last = bs_block_end * 64 + bs_end;
        
        /* No enabled elements found in table */
        if (first == cur_last) {
            goto done;
        }

        /* If multiple bitsets are evaluated, make sure each subsequent range
         * is equal or a subset of the previous range */
        if (i) {
            /* If the first element of a subsequent bitset is larger than the
             * previous last value, start over. */
            if (first >= last) {
                i = -1;
                continue;
            }

            /* Make sure the last element of the range doesn't exceed the last
             * element of the previous range. */
            if (cur_last > last) {
                cur_last = last;
            }
        }
        
        last = cur_last;
        int32_t elem_count = last - first;

        /* Make sure last element doesn't exceed total number of elements in 
         * the table */
        if (elem_count > bs_elem_count) {
            elem_count = bs_elem_count;
        }
        
        cur->first = first;
        cur->count = elem_count;
        iter->bitset_first = first;
    }
    
    /* Keep track of last processed element for iteration */ 
    iter->bitset_first = last;

    return 0;
done:
    return -1;
}

static
void mark_columns_dirty(
    ecs_query_t *query,
    ecs_matched_table_t *table_data)
{
    ecs_table_t *table = table_data->iter_data.table;

    if (table && table->dirty_state) {
        ecs_term_t *terms = query->filter.terms;
        int32_t c = 0, i, count = query->filter.term_count;
        for (i = 0; i < count; i ++) {
            ecs_term_t *term = &terms[i];
            ecs_term_id_t *subj = &term->args[0];
            if (term->inout != EcsIn && (term->inout != EcsInOutDefault || 
                (subj->entity == EcsThis && subj->set == EcsSelf)))
            {
                int32_t table_column = table_data->iter_data.columns[c];
                if (table_column > 0) {
                    table->dirty_state[table_column] ++;
                }
            }

            if (terms[i].oper == EcsOr) {
                do {
                    i ++;
                } while ((i < count) && terms[i].oper == EcsOr);
            }

            c ++;
        }
    }
}

/* Return next table */
bool ecs_query_next(
    ecs_iter_t *it)
{
    ecs_assert(it != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_query_iter_t *iter = &it->iter.query;
    ecs_page_iter_t *piter = &iter->page_iter;
    ecs_query_t *query = it->query;
    ecs_world_t *world = query->world;
    (void)world;

    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);

    if (!query->constraints_satisfied) {
        return false;
    }

    ecs_table_slice_t *slice = ecs_vector_first(
        query->table_slices, ecs_table_slice_t);
    ecs_matched_table_t *tables = ecs_vector_first(
        query->tables, ecs_matched_table_t);

    ecs_assert(!slice || query->compare, ECS_INTERNAL_ERROR, NULL);
    
    ecs_page_cursor_t cur;
    int32_t table_count = it->table_count;
    int32_t prev_count = it->total_count;

    int i;
    for (i = iter->index; i < table_count; i ++) {
        ecs_matched_table_t *table_data = slice ? slice[i].table : &tables[i];
        ecs_table_t *table = table_data->iter_data.table;
        ecs_data_t *data = NULL;

        iter->index = i + 1;
        
        if (table) {
            ecs_vector_t *bitset_columns = table_data->bitset_columns;
            ecs_vector_t *sparse_columns = table_data->sparse_columns;
            data = ecs_table_get_data(table);
            ecs_assert(data != NULL, ECS_INTERNAL_ERROR, NULL);
            it->table_columns = data->columns;
            
            if (slice) {
                cur.first = slice[i].start_row;
                cur.count = slice[i].count;                
            } else {
                cur.first = 0;
                cur.count = ecs_table_count(table);
            }

            if (cur.count) {
                if (bitset_columns) {
            
                    if (bitset_column_next(table, bitset_columns, iter, 
                        &cur) == -1) 
                    {
                        /* No more enabled components for table */
                        continue; 
                    } else {
                        iter->index = i;
                    }
                }

                if (sparse_columns) {
                    if (sparse_column_next(table, table_data,
                        sparse_columns, iter, &cur) == -1)
                    {
                        /* No more elements in sparse column */
                        continue;    
                    } else {
                        iter->index = i;
                    }
                }

                int ret = ecs_page_iter_next(piter, &cur);
                if (ret < 0) {
                    return false;
                } else if (ret > 0) {
                    continue;
                }
            } else {
                continue;
            }

            ecs_entity_t *entity_buffer = ecs_vector_first(
                data->entities, ecs_entity_t); 
            it->entities = &entity_buffer[cur.first];
            it->offset = cur.first;
            it->count = cur.count;
            it->total_count = cur.count;
        }

        it->table = &table_data->iter_data;
        it->frame_offset += prev_count;

        if (query->flags & EcsQueryHasOutColumns) {
            if (table) {
                mark_columns_dirty(query, table_data);
            }
        }

        return true;
    }

    return false;
}

bool ecs_query_next_w_filter(
    ecs_iter_t *iter,
    const ecs_filter_t *filter)
{
    ecs_table_t *table;

    do {
        if (!ecs_query_next(iter)) {
            return false;
        }
        table = iter->table->table;
    } while (filter && !ecs_table_match_filter(iter->world, table, filter));
    
    return true;
}

bool ecs_query_next_worker(
    ecs_iter_t *it,
    int32_t current,
    int32_t total)
{
    int32_t per_worker, first, prev_offset = it->offset;

    do {
        if (!ecs_query_next(it)) {
            return false;
        }

        int32_t count = it->count;
        per_worker = count / total;
        first = per_worker * current;

        count -= per_worker * total;

        if (count) {
            if (current < count) {
                per_worker ++;
                first += current;
            } else {
                first += count;
            }
        }

        if (!per_worker && !(it->query->flags & EcsQueryNeedsTables)) {
            if (current == 0) {
                return true;
            } else {
                return false;
            }
        }
    } while (!per_worker);

    it->frame_offset -= prev_offset;
    it->count = per_worker;
    it->offset += first;
    it->entities = &it->entities[first];
    it->frame_offset += first;

    return true;
}

void ecs_query_order_by(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_entity_t sort_component,
    ecs_compare_action_t compare)
{
    ecs_assert(query != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!(query->flags & EcsQueryIsOrphaned), ECS_INVALID_PARAMETER, NULL);    
    ecs_assert(query->flags & EcsQueryNeedsTables, ECS_INVALID_PARAMETER, NULL);

    query->sort_on_component = sort_component;
    query->compare = compare;

    ecs_vector_free(query->table_slices);
    query->table_slices = NULL;

    sort_tables(world, query);    

    if (!query->table_slices) {
        build_sorted_tables(query);
    }
}

void ecs_query_group_by(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_entity_t sort_component,
    ecs_rank_type_action_t group_table_action)
{
    ecs_assert(query != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!(query->flags & EcsQueryIsOrphaned), ECS_INVALID_PARAMETER, NULL);    
    ecs_assert(query->flags & EcsQueryNeedsTables, ECS_INVALID_PARAMETER, NULL);

    query->rank_on_component = sort_component;
    query->group_table = group_table_action;

    group_tables(world, query);

    order_ranked_tables(world, query);

    build_sorted_tables(query);
}

bool ecs_query_changed(
    ecs_query_t *query)
{
    ecs_assert(query != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!(query->flags & EcsQueryIsOrphaned), ECS_INVALID_PARAMETER, NULL);
    return tables_dirty(query);
}

bool ecs_query_orphaned(
    ecs_query_t *query)
{
    return query->flags & EcsQueryIsOrphaned;
}

const EcsComponent* ecs_component_from_id(
    const ecs_world_t *world,
    ecs_entity_t e)
{
    ecs_entity_t pair = 0;

    /* If this is a pair, get the pair component from the identifier */
    if (ECS_HAS_ROLE(e, PAIR)) {
        pair = e;
        e = ecs_get_alive(world, ECS_PAIR_RELATION(e));
    }

    const EcsComponent *component = ecs_get(world, e, EcsComponent);
    if ((!component || !component->size) && pair) {
        /* If this is a pair column and the pair is not a component, use
         * the component type of the component the pair is applied to. */
        e = ECS_PAIR_OBJECT(pair);

        /* Because generations are not stored in the pair, get the currently
         * alive id */
        e = ecs_get_alive(world, e);

        /* If a pair is used with a not alive id, the pair is not valid */
        ecs_assert(e != 0, ECS_INTERNAL_ERROR, NULL);

        component = ecs_get(world, e, EcsComponent);
    }

    return component;
}

/* Count number of columns with data (excluding tags) */
static
int32_t data_column_count(
    ecs_world_t * world,
    ecs_table_t * table)
{
    int32_t count = 0;
    ecs_vector_each(table->type, ecs_entity_t, c_ptr, {
        ecs_entity_t component = *c_ptr;

        /* Typically all components will be clustered together at the start of
         * the type as components are created from a separate id pool, and type
         * vectors are sorted. 
         * Explicitly check for EcsComponent and EcsName since the ecs_has check
         * doesn't work during bootstrap. */
        if ((component == ecs_id(EcsComponent)) || 
            (component == ecs_id(EcsName)) || 
            ecs_component_from_id(world, component) != NULL) 
        {
            count = c_ptr_i + 1;
        }
    });

    return count;
}

/* Ensure the ids used in the columns exist */
static
int32_t ensure_columns(
    ecs_world_t * world,
    ecs_table_t * table)
{
    int32_t count = 0;
    ecs_vector_each(table->type, ecs_entity_t, c_ptr, {
        ecs_entity_t component = *c_ptr;

        if (ECS_HAS_ROLE(component, PAIR)) {
            ecs_entity_t rel = ECS_PAIR_RELATION(component);
            ecs_entity_t obj = ECS_PAIR_OBJECT(component);
            ecs_ensure(world, rel);
            ecs_ensure(world, obj);
        } else if (component & ECS_ROLE_MASK) {
            ecs_entity_t e = ECS_PAIR_OBJECT(component);
            ecs_ensure(world, e);
        } else {
            ecs_ensure(world, component);
        }
    });

    return count;
}

/* Count number of switch columns */
static
int32_t switch_column_count(
    ecs_table_t *table)
{
    int32_t count = 0;
    ecs_vector_each(table->type, ecs_entity_t, c_ptr, {
        ecs_entity_t component = *c_ptr;

        if (ECS_HAS_ROLE(component, SWITCH)) {
            if (!count) {
                table->sw_column_offset = c_ptr_i;
            }
            count ++;
        }
    });

    return count;
}

/* Count number of bitset columns */
static
int32_t bitset_column_count(
    ecs_table_t *table)
{
    int32_t count = 0;
    ecs_vector_each(table->type, ecs_entity_t, c_ptr, {
        ecs_entity_t component = *c_ptr;

        if (ECS_HAS_ROLE(component, DISABLED)) {
            if (!count) {
                table->bs_column_offset = c_ptr_i;
            }
            count ++;
        }
    });

    return count;
}

static
ecs_type_t entities_to_type(
    ecs_entities_t *entities)
{
    if (entities->count) {
        ecs_vector_t *result = NULL;
        ecs_vector_set_count(&result, ecs_entity_t, entities->count);
        ecs_entity_t *array = ecs_vector_first(result, ecs_entity_t);
        ecs_os_memcpy(array, entities->array, ECS_SIZEOF(ecs_entity_t) * entities->count);
        return result;
    } else {
        return NULL;
    }
}

static
ecs_edge_t* get_edge(
    ecs_table_t *node,
    ecs_entity_t e)
{
    if (e < ECS_HI_COMPONENT_ID) {
        if (!node->lo_edges) {
            node->lo_edges = ecs_os_calloc(sizeof(ecs_edge_t) * ECS_HI_COMPONENT_ID);
        }
        return &node->lo_edges[e];
    } else {
        if (!node->hi_edges) {
            node->hi_edges = ecs_map_new(ecs_edge_t, 1);
        }
        return ecs_map_ensure(node->hi_edges, ecs_edge_t, e);
    }
}

static
void init_edges(
    ecs_world_t * world,
    ecs_table_t * table)
{
    ecs_entity_t *entities = ecs_vector_first(table->type, ecs_entity_t);
    int32_t count = ecs_vector_count(table->type);

    table->lo_edges = NULL;
    table->hi_edges = NULL;
    
    /* Make add edges to own components point to self */
    int32_t i;
    for (i = 0; i < count; i ++) {
        ecs_entity_t e = entities[i];

        ecs_edge_t *edge = get_edge(table, e);
        ecs_assert(edge != NULL, ECS_INTERNAL_ERROR, NULL);
        edge->add = table;

        if (count == 1) {
            edge->remove = &world->store.root;
        }

        /* As we're iterating over the table components, also set the table
         * flags. These allow us to quickly determine if the table contains
         * data that needs to be handled in a special way, like prefabs or 
         * containers */
        if (e <= EcsLastInternalComponentId || e == EcsModule) {
            table->flags |= EcsTableHasBuiltins;
        }

        if (e == EcsPrefab) {
            table->flags |= EcsTableIsPrefab;
            table->flags |= EcsTableIsDisabled;
        }

        if (e == EcsDisabled) {
            table->flags |= EcsTableIsDisabled;
        }

        if (e == ecs_id(EcsComponent)) {
            table->flags |= EcsTableHasComponentData;
        }

        if (ECS_HAS_ROLE(e, XOR)) {
            table->flags |= EcsTableHasXor;
        }

        if (ECS_HAS_RELATION(e, EcsIsA)) {
            table->flags |= EcsTableHasBase;
        }

        if (ECS_HAS_ROLE(e, SWITCH)) {
            table->flags |= EcsTableHasSwitch;
        }

        if (ECS_HAS_ROLE(e, DISABLED)) {
            table->flags |= EcsTableHasDisabled;
        }   

        ecs_entity_t obj = 0;

        if (ECS_HAS_RELATION(e, EcsChildOf)) {
            obj = ecs_pair_object(world, e);
            if (obj == EcsFlecs || obj == EcsFlecsCore || 
                ecs_has_id(world, obj, EcsModule)) 
            {
                table->flags |= EcsTableHasBuiltins;
            }

            e = ecs_pair(EcsChildOf, obj);
            table->flags |= EcsTableHasParent;
        }       

        if (ECS_HAS_RELATION(e, EcsChildOf) || ECS_HAS_RELATION(e, EcsIsA)) {
            ecs_set_watch(world, ecs_pair_object(world, e));
        }        
    }

    ecs_register_table(world, table);

    /* Register component info flags for all columns */
    ecs_table_notify(world, table, &(ecs_table_event_t){
        .kind = EcsTableComponentInfo
    });
}

static
void init_table(
    ecs_world_t * world,
    ecs_table_t * table,
    ecs_entities_t * entities)
{
    table->type = entities_to_type(entities);
    table->c_info = NULL;
    table->data = NULL;
    table->flags = 0;
    table->dirty_state = NULL;
    table->monitors = NULL;
    table->on_set = NULL;
    table->on_set_all = NULL;
    table->on_set_override = NULL;
    table->un_set_all = NULL;
    table->alloc_count = 0;

    /* Ensure the component ids for the table exist */
    ensure_columns(world, table);

    table->queries = NULL;
    table->column_count = data_column_count(world, table);
    table->sw_column_count = switch_column_count(table);
    table->bs_column_count = bitset_column_count(table);

    init_edges(world, table);
}

static
ecs_table_t *create_table(
    ecs_world_t * world,
    ecs_entities_t * entities,
    uint64_t hash)
{
    ecs_table_t *result = ecs_sparse_add(world->store.tables, ecs_table_t);
    result->id = ecs_sparse_last_id(world->store.tables);

    ecs_assert(result != NULL, ECS_INTERNAL_ERROR, NULL);
    init_table(world, result, entities);

#ifndef NDEBUG
    char *expr = ecs_type_str(world, result->type);
    ecs_trace_2("table #[green][%s]#[normal] created", expr);
    ecs_os_free(expr);
#endif
    ecs_log_push();

    /* Store table in lookup map */
    ecs_vector_t *tables = ecs_map_get_ptr(world->store.table_map, ecs_vector_t*, hash);
    ecs_table_t **elem = ecs_vector_add(&tables, ecs_table_t*);
    *elem = result;
    ecs_map_set(world->store.table_map, hash, &tables);

    ecs_notify_queries(world, &(ecs_query_event_t) {
        .kind = EcsQueryTableMatch,
        .table = result
    });

    ecs_log_pop();

    return result;
}

static
void add_entity_to_type(
    ecs_type_t type,
    ecs_entity_t add,
    ecs_entity_t replace,
    ecs_entities_t *out)
{
    int32_t count = ecs_vector_count(type);
    ecs_entity_t *array = ecs_vector_first(type, ecs_entity_t);    
    bool added = false;

    int32_t i, el = 0;
    for (i = 0; i < count; i ++) {
        ecs_entity_t e = array[i];
        if (e == replace) {
            continue;
        }

        if (e > add && !added) {
            out->array[el ++] = add;
            added = true;
        }
        
        out->array[el ++] = e;

        ecs_assert(el <= out->count, ECS_INTERNAL_ERROR, NULL);
    }

    if (!added) {
        out->array[el ++] = add;
    }

    out->count = el;

    ecs_assert(out->count != 0, ECS_INTERNAL_ERROR, NULL);
}

static
void remove_entity_from_type(
    ecs_type_t type,
    ecs_entity_t remove,
    ecs_entities_t *out)
{
    int32_t count = ecs_vector_count(type);
    ecs_entity_t *array = ecs_vector_first(type, ecs_entity_t);

    int32_t i, el = 0;
    for (i = 0; i < count; i ++) {
        ecs_entity_t e = array[i];
        if (e != remove) {
            out->array[el ++] = e;
            ecs_assert(el <= count, ECS_INTERNAL_ERROR, NULL);
        }
    }

    out->count = el;
}

static
void create_backlink_after_add(
    ecs_table_t * next,
    ecs_table_t * prev,
    ecs_entity_t add)
{
    ecs_edge_t *edge = get_edge(next, add);
    if (!edge->remove) {
        edge->remove = prev;
    }
}

static
void create_backlink_after_remove(
    ecs_table_t * next,
    ecs_table_t * prev,
    ecs_entity_t add)
{
    ecs_edge_t *edge = get_edge(next, add);
    if (!edge->add) {
        edge->add = prev;
    }
}

static
ecs_entity_t find_xor_replace(
    ecs_world_t * world,
    ecs_table_t * table,
    ecs_type_t type,
    ecs_entity_t add)
{
    if (table->flags & EcsTableHasXor) {
        ecs_entity_t *array = ecs_vector_first(type, ecs_entity_t);
        int32_t i, type_count = ecs_vector_count(type);
        ecs_type_t xor_type = NULL;

        for (i = type_count - 1; i >= 0; i --) {
            ecs_entity_t e = array[i];
            if (ECS_HAS_ROLE(e, XOR)) {
                ecs_entity_t e_type = e & ECS_COMPONENT_MASK;
                const EcsType *type_ptr = ecs_get(world, e_type, EcsType);
                ecs_assert(type_ptr != NULL, ECS_INTERNAL_ERROR, NULL);

                if (ecs_type_owns_id(
                    world, type_ptr->normalized, add, true)) 
                {
                    xor_type = type_ptr->normalized;
                }
            } else if (xor_type) {
                if (ecs_type_owns_id(world, xor_type, e, true)) {
                    return e;
                }
            }
        }
    }

    return 0;
}

int32_t ecs_table_switch_from_case(
    const ecs_world_t * world,
    const ecs_table_t * table,
    ecs_entity_t add)
{
    ecs_type_t type = table->type;
    ecs_data_t *data = ecs_table_get_data(table);
    ecs_entity_t *array = ecs_vector_first(type, ecs_entity_t);

    int32_t i, count = table->sw_column_count;
    ecs_assert(count != 0, ECS_INTERNAL_ERROR, NULL);

    add = add & ECS_COMPONENT_MASK;

    ecs_sw_column_t *sw_columns = NULL;

    if (data && (sw_columns = data->sw_columns)) {
        /* Fast path, we can get the switch type from the column data */
        for (i = 0; i < count; i ++) {
            ecs_type_t sw_type = sw_columns[i].type;
            if (ecs_type_owns_id(world, sw_type, add, true)) {
                return i;
            }
        }
    } else {
        /* Slow path, table is empty, so we'll have to get the switch types by
         * actually inspecting the switch type entities. */
        for (i = 0; i < count; i ++) {
            ecs_entity_t e = array[i + table->sw_column_offset];
            ecs_assert(ECS_HAS_ROLE(e, SWITCH), ECS_INTERNAL_ERROR, NULL);
            e = e & ECS_COMPONENT_MASK;

            const EcsType *type_ptr = ecs_get(world, e, EcsType);
            ecs_assert(type_ptr != NULL, ECS_INTERNAL_ERROR, NULL);

            if (ecs_type_owns_id(
                world, type_ptr->normalized, add, true)) 
            {
                return i;
            }
        }
    }

    /* If a table was not found, this is an invalid switch case */
    ecs_abort(ECS_INVALID_CASE, NULL);

    return -1;
}

static
ecs_table_t *find_or_create_table_include(
    ecs_world_t * world,
    ecs_table_t * node,
    ecs_entity_t add)
{
    /* If table has one or more switches and this is a case, return self */
    if (ECS_HAS_ROLE(add, CASE)) {
        ecs_assert((node->flags & EcsTableHasSwitch) != 0, 
            ECS_INVALID_CASE, NULL);
        return node;
    } else {
        ecs_type_t type = node->type;
        int32_t count = ecs_vector_count(type);

        ecs_entities_t entities = {
            .array = ecs_os_alloca(ECS_SIZEOF(ecs_entity_t) * (count + 1)),
            .count = count + 1
        };

        /* If table has a XOR column, check if the entity that is being added to
         * the table is part of the XOR type, and if it is, find the current 
         * entity in the table type matching the XOR type. This entity must be 
         * replaced in the new table, to ensure the XOR constraint isn't 
         * violated. */
        ecs_entity_t replace = find_xor_replace(world, node, type, add);

        add_entity_to_type(type, add, replace, &entities);

        ecs_table_t *result = ecs_table_find_or_create(world, &entities);
        
        if (result != node) {
            create_backlink_after_add(result, node, add);
        }

        return result;
    }
}

static
ecs_table_t *find_or_create_table_exclude(
    ecs_world_t * world,
    ecs_table_t * node,
    ecs_entity_t remove)
{
    ecs_type_t type = node->type;
    int32_t count = ecs_vector_count(type);

    ecs_entities_t entities = {
        .array = ecs_os_alloca(ECS_SIZEOF(ecs_entity_t) * count),
        .count = count
    };

    remove_entity_from_type(type, remove, &entities);

    ecs_table_t *result = ecs_table_find_or_create(world, &entities);
    if (!result) {
        return NULL;
    }

    if (result != node) {
        create_backlink_after_remove(result, node, remove);
    }

    return result;    
}

ecs_table_t* ecs_table_traverse_remove(
    ecs_world_t * world,
    ecs_table_t * node,
    ecs_entities_t * to_remove,
    ecs_entities_t * removed)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);
    
    int32_t i, count = to_remove->count;
    ecs_entity_t *entities = to_remove->array;
    node = node ? node : &world->store.root;

    for (i = 0; i < count; i ++) {
        ecs_entity_t e = entities[i];

        /* Removing 0 from an entity is not valid */
        ecs_assert(e != 0, ECS_INVALID_PARAMETER, NULL);

        ecs_edge_t *edge = get_edge(node, e);
        ecs_table_t *next = edge->remove;

        if (!next) {
            if (edge->add == node) {
                /* Find table with all components of node except 'e' */
                next = find_or_create_table_exclude(world, node, e);
                if (!next) {
                    return NULL;
                }

                edge->remove = next;
            } else {
                /* If the add edge does not point to self, the table
                 * does not have the entity in to_remove. */
                continue;
            }
        }

        bool has_case = ECS_HAS_ROLE(e, CASE);
        if (removed && (node != next || has_case)) {
            removed->array[removed->count ++] = e; 
        }

        node = next;
    }    

    return node;
}

static
void find_owned_components(
    ecs_world_t * world,
    ecs_table_t * node,
    ecs_entity_t base,
    ecs_entities_t * owned)
{
    /* If we're adding an IsA relationship, check if the base
     * has OWNED components that need to be added to the instance */
    ecs_type_t t = ecs_get_type(world, base);

    int i, count = ecs_vector_count(t);
    ecs_entity_t *entities = ecs_vector_first(t, ecs_entity_t);
    for (i = 0; i < count; i ++) {
        ecs_entity_t e = entities[i];
        if (ECS_HAS_RELATION(e, EcsIsA)) {
            find_owned_components(world, node, ECS_PAIR_OBJECT(e), owned);
        } else
        if (ECS_HAS_ROLE(e, OWNED)) {
            e = e & ECS_COMPONENT_MASK;
            
            /* If entity is a type, add each component in the type */
            const EcsType *t_ptr = ecs_get(world, e, EcsType);
            if (t_ptr) {
                ecs_type_t n = t_ptr->normalized;
                int32_t j, n_count = ecs_vector_count(n);
                ecs_entity_t *n_entities = ecs_vector_first(n, ecs_entity_t);
                for (j = 0; j < n_count; j ++) {
                    owned->array[owned->count ++] = n_entities[j];
                }
            } else {
                owned->array[owned->count ++] = ECS_PAIR_OBJECT(e);
            }
        }
    }
}

ecs_table_t* ecs_table_traverse_add(
    ecs_world_t * world,
    ecs_table_t * node,
    ecs_entities_t * to_add,
    ecs_entities_t * added)    
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);

    int32_t i, count = to_add->count;
    ecs_entity_t *entities = to_add->array;
    node = node ? node : &world->store.root;

    ecs_entity_t owned_array[ECS_MAX_ADD_REMOVE];
    ecs_entities_t owned = {
        .array = owned_array,
        .count = 0
    };    

    for (i = 0; i < count; i ++) {
        ecs_entity_t e = entities[i];

        /* Adding 0 to an entity is not valid */
        ecs_assert(e != 0, ECS_INVALID_PARAMETER, NULL);

        ecs_edge_t *edge = get_edge(node, e);
        ecs_table_t *next = edge->add;

        if (!next) {
            next = find_or_create_table_include(world, node, e);
            ecs_assert(next != NULL, ECS_INTERNAL_ERROR, NULL);
            edge->add = next;
        }

        bool has_case = ECS_HAS_ROLE(e, CASE);
        if (added && (node != next || has_case)) {
            added->array[added->count ++] = e; 
        }

        if ((node != next) && ECS_HAS_RELATION(e, EcsIsA)) {
            find_owned_components(
                world, next, ecs_pair_object(world, e), &owned);
        }        

        node = next;
    }

    /* In case OWNED components were found, add them as well */
    if (owned.count) {
        node = ecs_table_traverse_add(world, node, &owned, added);
    }

    return node;
}

static
bool ecs_entity_array_is_ordered(
    ecs_entities_t *entities)
{
    ecs_entity_t prev = 0;
    ecs_entity_t *array = entities->array;
    int32_t i, count = entities->count;

    for (i = 0; i < count; i ++) {
        if (!array[i] && !prev) {
            continue;
        }
        if (array[i] <= prev) {
            return false;
        }
        prev = array[i];
    }    

    return true;
}

static
int32_t ecs_entity_array_dedup(
    ecs_entity_t *array,
    int32_t count)
{
    int32_t j, k;
    ecs_entity_t prev = array[0];

    for (k = j = 1; k < count; j ++, k++) {
        ecs_entity_t e = array[k];
        if (e == prev) {
            k ++;
        }

        array[j] = e;
        prev = e;
    }

    return count - (k - j);
}

#ifndef NDEBUG

static
int32_t count_occurrences(
    ecs_world_t * world,
    ecs_entities_t * entities,
    ecs_entity_t entity,
    int32_t constraint_index)    
{
    const EcsType *type_ptr = ecs_get(world, entity, EcsType);
    ecs_assert(type_ptr != NULL, 
        ECS_INVALID_PARAMETER, "flag must be applied to type");

    ecs_type_t type = type_ptr->normalized;
    int32_t count = 0;
    
    int i;
    for (i = 0; i < constraint_index; i ++) {
        ecs_entity_t e = entities->array[i];
        if (e & ECS_ROLE_MASK) {
            break;
        }

        if (ecs_type_has_id(world, type, e)) {
            count ++;
        }
    }

    return count;
}

static
void verify_constraints(
    ecs_world_t * world,
    ecs_entities_t * entities)
{
    int i, count = entities->count;
    for (i = count - 1; i >= 0; i --) {
        ecs_entity_t e = entities->array[i];
        ecs_entity_t mask = e & ECS_ROLE_MASK;
        if (!mask || 
            ((mask != ECS_OR) &&
             (mask != ECS_XOR) &&
             (mask != ECS_NOT)))
        {
            break;
        }

        ecs_entity_t entity = e & ECS_COMPONENT_MASK;
        int32_t matches = count_occurrences(world, entities, entity, i);
        switch(mask) {
        case ECS_OR:
            ecs_assert(matches >= 1, ECS_TYPE_CONSTRAINT_VIOLATION, NULL);
            break;
        case ECS_XOR:
            ecs_assert(matches == 1, ECS_TYPE_CONSTRAINT_VIOLATION, NULL);
            break;
        case ECS_NOT:
            ecs_assert(matches == 0, ECS_TYPE_CONSTRAINT_VIOLATION, NULL);    
            break;
        }
    }
}

#endif

static
ecs_table_t *find_or_create(
    ecs_world_t * world,
    ecs_entities_t * entities)
{    
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);   

    /* Make sure array is ordered and does not contain duplicates */
    int32_t type_count = entities->count;
    ecs_entity_t *ordered = NULL;

    if (!type_count) {
        return &world->store.root;
    }

    if (!ecs_entity_array_is_ordered(entities)) {
        ecs_size_t size = ECS_SIZEOF(ecs_entity_t) * type_count;
        ordered = ecs_os_alloca(size);
        ecs_os_memcpy(ordered, entities->array, size);
        qsort(
            ordered, (size_t)type_count, sizeof(ecs_entity_t), ecs_entity_compare_qsort);
        type_count = ecs_entity_array_dedup(ordered, type_count);
    } else {
        ordered = entities->array;
    }

    uint64_t hash = 0;
    ecs_hash(ordered, entities->count * ECS_SIZEOF(ecs_entity_t), &hash);
    ecs_vector_t *table_vec = ecs_map_get_ptr(
        world->store.table_map, ecs_vector_t*, hash);
    if (table_vec) {
        /* Usually this will be just one, but in the case of a collision
         * multiple tables can be stored using the same hash. */
        int32_t i, count = ecs_vector_count(table_vec);
        ecs_table_t *table, **tables = ecs_vector_first(
            table_vec, ecs_table_t*);

        for (i = 0; i < count; i ++) {
            table = tables[i];
            int32_t t, table_type_count = ecs_vector_count(table->type);

            /* If number of components in table doesn't match, it's definitely
             * a collision. */
            if (table_type_count != type_count) {
                table = NULL;
                continue;
            }

            /* Check if components of table match */
            ecs_entity_t *table_type = ecs_vector_first(
                table->type, ecs_entity_t);
            for (t = 0; t < type_count; t ++) {
                if (table_type[t] != ordered[t]) {
                    table = NULL;
                    break;
                }
            }

            if (table) {
                return table;
            }
        }
    }

    /* If we get here, table needs to be created which is only allowed when the
     * application is not currently in progress */
    ecs_assert(!world->is_readonly, ECS_INTERNAL_ERROR, NULL);

    ecs_entities_t ordered_entities = {
        .array = ordered,
        .count = type_count
    };

#ifndef NDEBUG
    /* Check for constraint violations */
    verify_constraints(world, &ordered_entities);
#endif

    /* If we get here, the table has not been found, so create it. */
    ecs_table_t *result = create_table(world, &ordered_entities, hash);
    
    ecs_assert(ordered_entities.count == ecs_vector_count(result->type), 
        ECS_INTERNAL_ERROR, NULL);

    return result;
}

ecs_table_t* ecs_table_find_or_create(
    ecs_world_t * world,
    ecs_entities_t * components)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);   
    return find_or_create(world, components);
}

ecs_table_t* ecs_table_from_type(
    ecs_world_t *world,
    ecs_type_t type)
{
    ecs_entities_t components = ecs_type_to_entities(type);
    return ecs_table_find_or_create(
        world, &components);
}

void ecs_init_root_table(
    ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);   

    ecs_entities_t entities = {
        .array = NULL,
        .count = 0
    };

    init_table(world, &world->store.root, &entities);
}

void ecs_table_clear_edges(
    ecs_world_t *world,
    ecs_table_t *table)
{
    (void)world;
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);   

    uint32_t i;

    if (table->lo_edges) {
        for (i = 0; i < ECS_HI_COMPONENT_ID; i ++) {
            ecs_edge_t *e = &table->lo_edges[i];
            ecs_table_t *add = e->add, *remove = e->remove;
            if (add) {
                add->lo_edges[i].remove = NULL;
            }
            if (remove) {
                remove->lo_edges[i].add = NULL;
            }
        }
    }

    ecs_map_iter_t it = ecs_map_iter(table->hi_edges);
    ecs_edge_t *edge;
    ecs_map_key_t component;
    while ((edge = ecs_map_next(&it, ecs_edge_t, &component))) {
        ecs_table_t *add = edge->add, *remove = edge->remove;
        if (add) {
            ecs_edge_t *e = get_edge(add, component);
            e->remove = NULL;
            if (!e->add) {
                ecs_map_remove(add->hi_edges, component);
            }
        }
        if (remove) {
            ecs_edge_t *e = get_edge(remove, component);
            e->add = NULL;
            if (!e->remove) {
                ecs_map_remove(remove->hi_edges, component);
            }
        }
    }
}

/* The ratio used to determine whether the map should rehash. If
 * (element_count * LOAD_FACTOR) > bucket_count, bucket count is increased. */
#define LOAD_FACTOR (1.5f)
#define KEY_SIZE (ECS_SIZEOF(ecs_map_key_t))
#define GET_ELEM(array, elem_size, index) \
    ECS_OFFSET(array, (elem_size) * (index))

struct ecs_bucket_t {
    ecs_map_key_t *keys;    /* Array with keys */
    void *payload;          /* Payload array */
    int32_t count;          /* Number of elements in bucket */
};

struct ecs_map_t {
    ecs_bucket_t *buckets;
    int32_t elem_size;
    int32_t bucket_count;
    int32_t count;
};

/* Get bucket count for number of elements */
static
int32_t get_bucket_count(
    int32_t element_count)
{
    return ecs_next_pow_of_2((int32_t)((float)element_count * LOAD_FACTOR));
}

/* Get bucket index for provided map key */
static
int32_t get_bucket_id(
    int32_t bucket_count,
    ecs_map_key_t key) 
{
    ecs_assert(bucket_count > 0, ECS_INTERNAL_ERROR, NULL);
    int32_t result = (int32_t)(key & ((uint64_t)bucket_count - 1));
    ecs_assert(result < INT32_MAX, ECS_INTERNAL_ERROR, NULL);
    return result;
}

/* Get bucket for key */
static
ecs_bucket_t* get_bucket(
    const ecs_map_t *map,
    ecs_map_key_t key)
{
    int32_t bucket_count = map->bucket_count;
    if (!bucket_count) {
        return NULL;
    }

    int32_t bucket_id = get_bucket_id(bucket_count, key);
    ecs_assert(bucket_id < bucket_count, ECS_INTERNAL_ERROR, NULL);

    return &map->buckets[bucket_id];
}

/* Ensure that map has at least new_count buckets */
static
void ensure_buckets(
    ecs_map_t *map,
    int32_t new_count)
{
    int32_t bucket_count = map->bucket_count;
    new_count = ecs_next_pow_of_2(new_count);
    if (new_count && new_count > bucket_count) {
        map->buckets = ecs_os_realloc(map->buckets, new_count * ECS_SIZEOF(ecs_bucket_t));
        map->bucket_count = new_count;

        ecs_os_memset(
            ECS_OFFSET(map->buckets, bucket_count * ECS_SIZEOF(ecs_bucket_t)), 
            0, (new_count - bucket_count) * ECS_SIZEOF(ecs_bucket_t));
    }
}

/* Free contents of bucket */
static
void clear_bucket(
    ecs_bucket_t *bucket)
{
    ecs_os_free(bucket->keys);
    ecs_os_free(bucket->payload);
    bucket->keys = NULL;
    bucket->payload = NULL;
    bucket->count = 0;
}

/* Clear all buckets */
static
void clear_buckets(
    ecs_map_t *map)
{
    ecs_bucket_t *buckets = map->buckets;
    int32_t i, count = map->bucket_count;
    for (i = 0; i < count; i ++) {
        clear_bucket(&buckets[i]);
    }
    ecs_os_free(buckets);
    map->buckets = NULL;
    map->bucket_count = 0;
}

/* Find or create bucket for specified key */
static
ecs_bucket_t* ensure_bucket(
    ecs_map_t *map,
    ecs_map_key_t key)
{
    if (!map->bucket_count) {
        ensure_buckets(map, 2);
    }

    int32_t bucket_id = get_bucket_id(map->bucket_count, key);
    ecs_assert(bucket_id >= 0, ECS_INTERNAL_ERROR, NULL);
    return &map->buckets[bucket_id];
}

/* Add element to bucket */
static
int32_t add_to_bucket(
    ecs_bucket_t *bucket,
    ecs_size_t elem_size,
    ecs_map_key_t key,
    const void *payload)
{
    int32_t index = bucket->count ++;
    int32_t bucket_count = index + 1;

    bucket->keys = ecs_os_realloc(bucket->keys, KEY_SIZE * bucket_count);
    bucket->payload = ecs_os_realloc(bucket->payload, elem_size * bucket_count);
    bucket->keys[index] = key;

    if (payload) {
        void *elem = GET_ELEM(bucket->payload, elem_size, index);
        ecs_os_memcpy(elem, payload, elem_size);
    }

    return index;
}

/*  Remove element from bucket */
static
void remove_from_bucket(
    ecs_bucket_t *bucket,
    ecs_size_t elem_size,
    ecs_map_key_t key,
    int32_t index)
{
    (void)key;

    ecs_assert(bucket->count != 0, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(index < bucket->count, ECS_INTERNAL_ERROR, NULL);
    
    int32_t bucket_count = -- bucket->count;

    if (index != bucket->count) {
        ecs_assert(key == bucket->keys[index], ECS_INTERNAL_ERROR, NULL);
        bucket->keys[index] = bucket->keys[bucket_count];

        ecs_map_key_t *elem = GET_ELEM(bucket->payload, elem_size, index);
        ecs_map_key_t *last_elem = GET_ELEM(bucket->payload, elem_size, bucket->count);

        ecs_os_memcpy(elem, last_elem, elem_size);
    }
}

/* Get payload pointer for key from bucket */
static
void* get_from_bucket(
    ecs_bucket_t *bucket,
    ecs_map_key_t key,
    ecs_size_t elem_size)
{
    ecs_map_key_t *keys = bucket->keys;
    int32_t i, count = bucket->count;

    for (i = 0; i < count; i ++) {
        if (keys[i] == key) {
            return GET_ELEM(bucket->payload, elem_size, i);
        }
    }
    return NULL;
}

/* Grow number of buckets */
static
void rehash(
    ecs_map_t *map,
    int32_t bucket_count)
{
    ecs_assert(bucket_count != 0, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(bucket_count > map->bucket_count, ECS_INTERNAL_ERROR, NULL);

    ecs_size_t elem_size = map->elem_size;

    ensure_buckets(map, bucket_count);

    ecs_bucket_t *buckets = map->buckets;
    ecs_assert(buckets != NULL, ECS_INTERNAL_ERROR, NULL);
    
    int32_t bucket_id;

    /* Iterate backwards as elements could otherwise be moved to existing
        * buckets which could temporarily cause the number of elements in a
        * bucket to exceed BUCKET_COUNT. */
    for (bucket_id = bucket_count - 1; bucket_id >= 0; bucket_id --) {
        ecs_bucket_t *bucket = &buckets[bucket_id];

        int i, count = bucket->count;
        ecs_map_key_t *key_array = bucket->keys;
        void *payload_array = bucket->payload;

        for (i = 0; i < count; i ++) {
            ecs_map_key_t key = key_array[i];
            void *elem = GET_ELEM(payload_array, elem_size, i);
            int32_t new_bucket_id = get_bucket_id(bucket_count, key);

            if (new_bucket_id != bucket_id) {
                ecs_bucket_t *new_bucket = &buckets[new_bucket_id];

                add_to_bucket(new_bucket, elem_size, key, elem);
                remove_from_bucket(bucket, elem_size, key, i);

                count --;
                i --;
            }
        }

        if (!bucket->count) {
            clear_bucket(bucket);
        }
    }
}

ecs_map_t* _ecs_map_new(
    ecs_size_t elem_size,
    ecs_size_t alignment, 
    int32_t element_count)
{
    (void)alignment;

    ecs_map_t *result = ecs_os_calloc(ECS_SIZEOF(ecs_map_t) * 1);
    ecs_assert(result != NULL, ECS_OUT_OF_MEMORY, NULL);

    int32_t bucket_count = get_bucket_count(element_count);

    result->count = 0;
    result->elem_size = elem_size;

    ensure_buckets(result, bucket_count);

    return result;
}

void ecs_map_free(
    ecs_map_t *map)
{
    if (map) {
        clear_buckets(map);
        ecs_os_free(map);
    }
}

void* _ecs_map_get(
    const ecs_map_t *map,
    ecs_size_t elem_size,
    ecs_map_key_t key)
{
    (void)elem_size;

    if (!map) {
        return NULL;
    }

    ecs_assert(elem_size == map->elem_size, ECS_INVALID_PARAMETER, NULL);

    ecs_bucket_t * bucket = get_bucket(map, key);
    if (!bucket) {
        return NULL;
    }

    return get_from_bucket(bucket, key, elem_size);
}

void* _ecs_map_get_ptr(
    const ecs_map_t *map,
    ecs_map_key_t key)
{
    void * ptr_ptr = _ecs_map_get(map, ECS_SIZEOF(void*), key);

    if (ptr_ptr) {
        return *(void**)ptr_ptr;
    } else {
        return NULL;
    }
}

void * _ecs_map_ensure(
    ecs_map_t *map,
    ecs_size_t elem_size,
    ecs_map_key_t key)
{
    void *result = _ecs_map_get(map, elem_size, key);
    if (!result) {
        result = _ecs_map_set(map, elem_size, key, NULL);
        ecs_assert(result != NULL, ECS_INTERNAL_ERROR, NULL);
        ecs_os_memset(result, 0, elem_size);
    }

    return result;
}

void* _ecs_map_set(
    ecs_map_t *map,
    ecs_size_t elem_size,
    ecs_map_key_t key,
    const void *payload)
{
    ecs_assert(map != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(elem_size == map->elem_size, ECS_INVALID_PARAMETER, NULL);

    ecs_bucket_t *bucket = ensure_bucket(map, key);
    ecs_assert(bucket != NULL, ECS_INTERNAL_ERROR, NULL);

    void *elem = get_from_bucket(bucket, key, elem_size);
    if (!elem) {
        int32_t index = add_to_bucket(bucket, elem_size, key, payload);
        
        int32_t map_count = ++map->count;
        int32_t target_bucket_count = get_bucket_count(map_count);
        int32_t map_bucket_count = map->bucket_count;

        if (target_bucket_count > map_bucket_count) {
            rehash(map, target_bucket_count);
            bucket = ensure_bucket(map, key);
            return get_from_bucket(bucket, key, elem_size);
        } else {
            return GET_ELEM(bucket->payload, elem_size, index);
        }       
    } else {
        if (payload) {
            ecs_os_memcpy(elem, payload, elem_size);
        }
        return elem;
    }
}

void ecs_map_remove(
    ecs_map_t *map,
    ecs_map_key_t key)
{
    ecs_assert(map != NULL, ECS_INVALID_PARAMETER, NULL);

    ecs_bucket_t * bucket = get_bucket(map, key);
    if (!bucket) {
        return;
    }

    int32_t i, bucket_count = bucket->count;
    for (i = 0; i < bucket_count; i ++) {
        if (bucket->keys[i] == key) {
            remove_from_bucket(bucket, map->elem_size, key, i);
            map->count --;
        }
    } 
}

int32_t ecs_map_count(
    const ecs_map_t *map)
{
    return map ? map->count : 0;
}

int32_t ecs_map_bucket_count(
    const ecs_map_t *map)
{
    return map ? map->bucket_count : 0;
}

void ecs_map_clear(
    ecs_map_t *map)
{
    ecs_assert(map != NULL, ECS_INVALID_PARAMETER, NULL);
    clear_buckets(map);
    map->count = 0;
}

ecs_map_iter_t ecs_map_iter(
    const ecs_map_t *map)
{
    return (ecs_map_iter_t){
        .map = map,
        .bucket = NULL,
        .bucket_index = 0,
        .element_index = 0
    };
}

void* _ecs_map_next(
    ecs_map_iter_t *iter,
    ecs_size_t elem_size,
    ecs_map_key_t *key_out)
{
    const ecs_map_t *map = iter->map;
    if (!map) {
        return NULL;
    }
    
    ecs_assert(!elem_size || elem_size == map->elem_size, ECS_INVALID_PARAMETER, NULL);
 
    ecs_bucket_t *bucket = iter->bucket;
    int32_t element_index = iter->element_index;
    elem_size = map->elem_size;

    do {
        if (!bucket) {
            int32_t bucket_index = iter->bucket_index;
            ecs_bucket_t *buckets = map->buckets;
            if (bucket_index < map->bucket_count) {
                bucket = &buckets[bucket_index];
                iter->bucket = bucket;

                element_index = 0;
                iter->element_index = 0;
            } else {
                return NULL;
            }
        }

        if (element_index < bucket->count) {
            iter->element_index = element_index + 1;
            break;
        } else {
            bucket = NULL;
            iter->bucket_index ++;
        }
    } while (true);
    
    if (key_out) {
        *key_out = bucket->keys[element_index];
    }

    return GET_ELEM(bucket->payload, elem_size, element_index);
}

void* _ecs_map_next_ptr(
    ecs_map_iter_t *iter,
    ecs_map_key_t *key_out)
{
    void *result = _ecs_map_next(iter, ECS_SIZEOF(void*), key_out);
    if (result) {
        return *(void**)result;
    } else {
        return NULL;
    }
}

void ecs_map_grow(
    ecs_map_t *map, 
    int32_t element_count)
{
    ecs_assert(map != NULL, ECS_INVALID_PARAMETER, NULL);
    int32_t target_count = map->count + element_count;
    int32_t bucket_count = get_bucket_count(target_count);

    if (bucket_count > map->bucket_count) {
        rehash(map, bucket_count);
    }
}

void ecs_map_set_size(
    ecs_map_t *map, 
    int32_t element_count)
{    
    ecs_assert(map != NULL, ECS_INVALID_PARAMETER, NULL);
    int32_t bucket_count = get_bucket_count(element_count);

    if (bucket_count) {
        rehash(map, bucket_count);
    }
}

void ecs_map_memory(
    ecs_map_t *map, 
    int32_t *allocd,
    int32_t *used)
{
    ecs_assert(map != NULL, ECS_INVALID_PARAMETER, NULL);

    if (used) {
        *used = map->count * map->elem_size;
    }

    if (allocd) {
        *allocd += ECS_SIZEOF(ecs_map_t);

        int i, bucket_count = map->bucket_count;
        for (i = 0; i < bucket_count; i ++) {
            ecs_bucket_t *bucket = &map->buckets[i];
            *allocd += KEY_SIZE * bucket->count;
            *allocd += map->elem_size * bucket->count;
        }

        *allocd += ECS_SIZEOF(ecs_bucket_t) * bucket_count;
    }
}

static
void* get_owned_column_ptr(
    const ecs_iter_t *it,
    ecs_size_t size,
    int32_t table_column,
    int32_t row)
{
    ecs_assert(it->table_columns != NULL, ECS_INTERNAL_ERROR, NULL);
    (void)size;

    ecs_column_t *column = &((ecs_column_t*)it->table_columns)[table_column - 1];
    ecs_assert(column->size != 0, ECS_COLUMN_HAS_NO_DATA, NULL);
    ecs_assert(!size || column->size == size, ECS_COLUMN_TYPE_MISMATCH, NULL);
    void *buffer = ecs_vector_first_t(column->data, column->size, column->alignment);
    return ECS_OFFSET(buffer, column->size * (it->offset + row));
}

static
const void* get_shared_column(
    const ecs_iter_t *it,
    ecs_size_t size,
    int32_t table_column)
{
    ecs_ref_t *refs = it->table->references;
    ecs_assert(refs != NULL, ECS_INTERNAL_ERROR, NULL);
    (void)size;

    ecs_ref_t *ref = &refs[-table_column - 1];
    if (!ref->component) {
        return NULL;
    }

#ifndef NDEBUG
    if (size) {
        ecs_entity_t component_id = ecs_get_typeid(
            it->world, refs[-table_column - 1].component);

        const EcsComponent *cdata = ecs_get(
            it->world, component_id, EcsComponent);

        ecs_assert(cdata != NULL, ECS_INTERNAL_ERROR, NULL);
        ecs_assert(cdata->size == size, ECS_COLUMN_TYPE_MISMATCH, 
            it->system ? ecs_get_name(it->world, it->system) : NULL);
    }
#endif

    return (void*)ecs_get_ref_w_id(
        it->world, ref, ref->entity, ref->component);
}

static
bool get_table_column(
    const ecs_iter_t *it,
    int32_t column,
    int32_t *table_column_out)
{
    ecs_assert(column <= it->column_count, ECS_INVALID_PARAMETER, NULL);

    int32_t table_column = 0;

    if (column != 0) {
        ecs_assert(it->table->columns != NULL, ECS_INTERNAL_ERROR, NULL);

        table_column = it->table->columns[column - 1];
        if (!table_column) {
            /* column is not set */
            return false;
        }
    }

    *table_column_out = table_column;

    return true;
}

static
void* get_term(
    const ecs_iter_t *it,
    ecs_size_t size,
    int32_t column,
    int32_t row)
{
    int32_t table_column;

    if (!column) {
        return it->entities;
    }

    if (!get_table_column(it, column, &table_column)) {
        return NULL;
    }

    if (table_column < 0) {
        return (void*)get_shared_column(it, size, table_column);
    } else {
        return get_owned_column_ptr(it, size, table_column, row);
    }
}


/* --- Public API --- */

void* ecs_term_w_size(
    const ecs_iter_t *it,
    size_t size,
    int32_t term)
{
    return get_term(it, ecs_from_size_t(size), term, 0);
}

bool ecs_term_is_owned(
    const ecs_iter_t *it,
    int32_t term)
{
    int32_t table_column;

    if (!get_table_column(it, term, &table_column)) {
        return true;
    }

    return table_column >= 0;
}

bool ecs_term_is_readonly(
    const ecs_iter_t *it,
    int32_t term_index)
{
    ecs_query_t *query = it->query;

    /* If this is not a query iterator, readonly is meaningless */
    ecs_assert(query != NULL, ECS_INVALID_OPERATION, NULL);
    (void)query;

    ecs_term_t *term = &it->query->filter.terms[term_index - 1];
    
    if (term->inout == EcsIn) {
        return true;
    } else {
        ecs_term_id_t *subj = &term->args[0];

        if (term->inout == EcsInOutDefault) {
            if (subj->entity != EcsThis) {
                return true;
            }

            if ((subj->set != EcsSelf) && (subj->set != EcsDefaultSet)) {
                return true;
            }
        }
    }
    
    return false;
}

ecs_entity_t ecs_term_source(
    const ecs_iter_t *it,
    int32_t index)
{
    ecs_assert(index <= it->column_count, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(index > 0, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(it->table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(it->table->columns != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_iter_table_t *table = it->table;
    int32_t table_column = table->columns[index - 1];
    if (table_column >= 0) {
        return 0;
    }

    ecs_assert(table->references != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_ref_t *ref = &table->references[-table_column - 1];
    return ref->entity;
}

ecs_id_t ecs_term_id(
    const ecs_iter_t *it,
    int32_t index)
{
    ecs_assert(index <= it->column_count, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(index > 0, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(it->table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(it->table->components != NULL, ECS_INTERNAL_ERROR, NULL);
    return it->table->components[index - 1];
}

size_t ecs_term_size(
    const ecs_iter_t *it,
    int32_t index)
{
    ecs_assert(index <= it->column_count, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(index > 0, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(it->table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(it->table->columns != NULL, ECS_INTERNAL_ERROR, NULL);
    int32_t table_column = it->table->columns[index - 1];
    return ecs_iter_column_size(it, table_column - 1);
}

ecs_type_t ecs_iter_type(
    const ecs_iter_t *it)
{
    /* If no table is set it means that the iterator isn't pointing to anything
     * yet. The most likely cause for this is that the operation is invoked on
     * a new iterator for which "next" hasn't been invoked yet, or on an
     * iterator that is out of elements. */
    ecs_assert(it->table != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_table_t *table = it->table->table;
    return table->type;
}

int32_t ecs_iter_find_column(
    const ecs_iter_t *it,
    ecs_entity_t component)
{
    /* See ecs_iter_type */    
    ecs_assert(it->table != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(it->table->table != NULL, ECS_INTERNAL_ERROR, NULL);
    return ecs_type_index_of(it->table->table->type, component);
}

void* ecs_iter_column_w_size(
    const ecs_iter_t *it,
    size_t size,
    int32_t column_index)
{
    /* See ecs_iter_type */ 
    ecs_assert(it->table != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(it->table->table != NULL, ECS_INTERNAL_ERROR, NULL);
    (void)size;
    
    ecs_table_t *table = it->table->table;
    ecs_assert(column_index < ecs_vector_count(table->type), 
        ECS_INVALID_PARAMETER, NULL);
    
    if (table->column_count <= column_index) {
        return NULL;
    }

    ecs_column_t *columns = it->table_columns;
    ecs_column_t *column = &columns[column_index];
    ecs_assert(!size || (ecs_size_t)size == column->size, ECS_INVALID_PARAMETER, NULL);

    return ecs_vector_first_t(column->data, column->size, column->alignment);
}

size_t ecs_iter_column_size(
    const ecs_iter_t *it,
    int32_t column_index)
{
    /* See ecs_iter_type */
    ecs_assert(it->table != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(it->table->table != NULL, ECS_INTERNAL_ERROR, NULL);
    
    ecs_table_t *table = it->table->table;
    ecs_assert(column_index < ecs_vector_count(table->type), 
        ECS_INVALID_PARAMETER, NULL);

    if (table->column_count <= column_index) {
        return 0;
    }

    ecs_column_t *columns = it->table_columns;
    ecs_column_t *column = &columns[column_index];
    
    return ecs_to_size_t(column->size);
}

// DEPRECATED
void* ecs_element_w_size(
    const ecs_iter_t *it, 
    size_t size,
    int32_t column,
    int32_t row)
{
    return get_term(it, ecs_from_size_t(size), column, row);
}

static
int32_t count_events(
    const ecs_entity_t *events) 
{
    int32_t i;

    for (i = 0; i < ECS_TRIGGER_DESC_EVENT_COUNT_MAX; i ++) {
        if (!events[i]) {
            break;
        }
    }

    return i;
} 

static
void register_id_trigger(
    ecs_map_t *set,
    ecs_trigger_t *trigger)
{
    ecs_trigger_t **t = ecs_map_ensure(set, ecs_trigger_t*, trigger->id);
    ecs_assert(t != NULL, ECS_INTERNAL_ERROR, NULL);
    *t = trigger;
}

static
ecs_map_t* unregister_id_trigger(
    ecs_map_t *set,
    ecs_trigger_t *trigger)
{
    ecs_map_remove(set, trigger->id);

    if (!ecs_map_count(set)) {
        ecs_map_free(set);
        return NULL;
    }

    return set;
}

static
void register_trigger(
    ecs_world_t *world,
    ecs_id_t id,
    ecs_trigger_t *trigger)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(trigger != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_map_t *triggers = world->id_triggers;
    ecs_assert(triggers != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_id_trigger_t *idt = ecs_map_ensure(triggers, 
        ecs_id_trigger_t, id);
    ecs_assert(idt != NULL, ECS_INTERNAL_ERROR, NULL);

    int i;
    for (i = 0; i < trigger->event_count; i ++) {
        if (trigger->events[i] == EcsOnAdd) {
            ecs_map_t *set = idt->on_add_triggers;
            if (!set) {
                set = idt->on_add_triggers = ecs_map_new(ecs_trigger_t*, 1);

                // First OnAdd trigger, send table notification
                ecs_notify_tables(world, id, &(ecs_table_event_t){
                    .kind = EcsTableTriggerMatch,
                    .event = EcsOnAdd
                });
            }
            register_id_trigger(set, trigger);
        } else
        if (trigger->events[i] == EcsOnRemove) {
            ecs_map_t *set = idt->on_remove_triggers;
            if (!set) {
                set = idt->on_remove_triggers = ecs_map_new(ecs_trigger_t*, 1);

                // First OnRemove trigger, send table notification
                ecs_notify_tables(world, id, &(ecs_table_event_t){
                    .kind = EcsTableTriggerMatch,
                    .event = EcsOnRemove
                });
            }

            register_id_trigger(set, trigger);            
        }
    }
}

static
void unregister_trigger(
    ecs_world_t *world,
    ecs_trigger_t *trigger)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(trigger != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_map_t *triggers = world->id_triggers;
    ecs_assert(triggers != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_id_trigger_t *idt = ecs_map_get(
        triggers, ecs_id_trigger_t, trigger->id);
    if (!idt) {
        return;
    }

    int i;
    for (i = 0; i < trigger->event_count; i ++) {
        if (trigger->events[i] == EcsOnAdd) {
            ecs_map_t *set = idt->on_add_triggers;
            if (!set) {
                return;
            }
            idt->on_add_triggers = unregister_id_trigger(set, trigger);
        } else
        if (trigger->events[i] == EcsOnRemove) {
            ecs_map_t *set = idt->on_remove_triggers;
            if (!set) {
                return;
            }
            idt->on_remove_triggers = unregister_id_trigger(set, trigger);
        }          
    }  
}

ecs_map_t* ecs_triggers_get(
    const ecs_world_t *world,
    ecs_id_t id,
    ecs_entity_t event)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(id != 0, ECS_INTERNAL_ERROR, NULL);

    ecs_map_t *triggers = world->id_triggers;
    ecs_assert(triggers != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_id_trigger_t *idt = ecs_map_get(triggers, ecs_id_trigger_t, id);
    if (!idt) {
        return NULL;
    }

    if (event == EcsOnAdd) {
        if (idt->on_add_triggers && ecs_map_count(idt->on_add_triggers)) {
            return idt->on_add_triggers;
        }
    } else if (event == EcsOnRemove) {
        if (idt->on_remove_triggers && ecs_map_count(idt->on_remove_triggers)) {
            return idt->on_remove_triggers;
        }
    }

    return NULL;
}

static
void notify_trigger_set(
    ecs_world_t *world,
    ecs_entity_t id,
    ecs_entity_t event,
    const ecs_map_t *triggers,
    ecs_table_t *table,
    ecs_data_t *data,
    int32_t row,
    int32_t count)
{
    if (!triggers) {
        return;
    }

    ecs_assert(!world->is_readonly, ECS_INTERNAL_ERROR, NULL);

    ecs_entity_t *entities = ecs_vector_first(data->entities, ecs_entity_t);        
    ecs_assert(entities != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(row < ecs_vector_count(data->entities), ECS_INTERNAL_ERROR, NULL);
    ecs_assert((row + count) <= ecs_vector_count(data->entities), 
        ECS_INTERNAL_ERROR, NULL);
    entities = ECS_OFFSET(entities, ECS_SIZEOF(ecs_entity_t) * row);

    int32_t index = ecs_type_index_of(table->type, id);
    ecs_assert(index >= 0, ECS_INTERNAL_ERROR, NULL);
    index ++;

    ecs_entity_t ids[1] = { id };
    int32_t columns[1] = { index };

    /* If there is no data, ensure that system won't try to get it */
    if (table->column_count < index) {
        columns[0] = 0;
    } else {
        ecs_column_t *column = &data->columns[index - 1];
        if (!column->size) {
            columns[0] = 0;
        }
    }

    ecs_type_t types[1] = { ecs_type_from_id(world, id) };

    ecs_iter_table_t table_data = {
        .table = table,
        .columns = columns,
        .components = ids,
        .types = types
    };

    ecs_iter_t it = {
        .world = world,
        .event = event,
        .table = &table_data,
        .table_count = 1,
        .inactive_table_count = 0,
        .column_count = 1,
        .table_columns = data->columns,
        .entities = entities,
        .offset = row,
        .count = count,
    }; 

    ecs_map_iter_t mit = ecs_map_iter(triggers);
    ecs_trigger_t *t;
    while ((t = ecs_map_next_ptr(&mit, ecs_trigger_t*, NULL))) {
        it.system = t->entity;
        it.param = t->ctx;
        t->action(&it);                   
    }
}

void ecs_triggers_notify(
    ecs_world_t *world,
    ecs_id_t id,
    ecs_entity_t event,
    ecs_table_t *table,
    ecs_data_t *data,
    int32_t row,
    int32_t count)
{
    notify_trigger_set(world, id, event,
        ecs_triggers_get(world, id, event), 
            table, data, row, count);

    if (ECS_HAS_ROLE(id, PAIR)) {
        ecs_entity_t pred = ECS_PAIR_RELATION(id);
        ecs_entity_t obj = ECS_PAIR_OBJECT(id);

        notify_trigger_set(world, id, event,
            ecs_triggers_get(world, ecs_pair(pred, EcsWildcard), event), 
                table, data, row, count);

        notify_trigger_set(world, id, event, 
            ecs_triggers_get(world, ecs_pair(EcsWildcard, obj), event), 
                table, data, row, count);

        notify_trigger_set(world, id, event, 
            ecs_triggers_get(world, ecs_pair(EcsWildcard, EcsWildcard), event), 
                table, data, row, count);                                
    } else {
        notify_trigger_set(world, id, event, 
            ecs_triggers_get(world, EcsWildcard, event), 
                table, data, row, count);
    }
}

ecs_entity_t ecs_trigger_init(
    ecs_world_t *world,
    const ecs_trigger_desc_t *desc)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(desc != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(desc->callback != NULL, ECS_INVALID_PARAMETER, NULL);

    char *name = NULL;
    const char *expr = desc->expr;

    /* If entity is provided, create it */
    ecs_entity_t entity = ecs_entity_init(world, &desc->entity);

    /* Something went wrong with the construction of the entity */
    ecs_assert(entity != 0, ECS_INVALID_PARAMETER, NULL);
    name = ecs_get_fullpath(world, entity);

    ecs_term_t term;
    if (expr) {
#ifdef FLECS_PARSER
        const char *ptr = ecs_parse_term(world, name, expr, expr, &term);
        if (!ptr) {
            goto error;
        }

        if (!ecs_term_is_set(&term)) {
            ecs_parser_error(name, expr, 0, "invalid empty trigger expression");
            goto error;
        }

        if (ptr[0]) {
            ecs_parser_error(name, expr, 0, 
                "too many terms in trigger expression (expected 1)");
            goto error;
        }
#else
        ecs_abort(ECS_UNSUPPORTED, "parser addon is not available");
#endif
    } else {
        term = desc->term;
    }

    if (ecs_term_finalize(world, name, expr, &term)) {
        goto error;
    }

    /* Currently triggers are not supported for specific entities */
    ecs_assert(term.args[0].entity == EcsThis, ECS_UNSUPPORTED, NULL);

    ecs_trigger_t *trigger = ecs_sparse_add(world->triggers, ecs_trigger_t);
    trigger->term = term;
    trigger->action = desc->callback;
    trigger->ctx = desc->ctx;
    trigger->event_count = count_events(desc->events);
    ecs_os_memcpy(trigger->events, desc->events, 
        trigger->event_count * ECS_SIZEOF(ecs_entity_t));
    trigger->id = ecs_sparse_last_id(world->triggers);
    trigger->entity = entity;

    ecs_set(world, entity, EcsTrigger, {trigger});

    /* Trigger must have at least one event */
    ecs_assert(trigger->event_count != 0, ECS_INVALID_PARAMETER, NULL);

    register_trigger(world, trigger->term.id, trigger);

    ecs_term_fini(&term);

    ecs_os_free(name);
    return entity;
error:
    ecs_os_free(name);
    return 0;
}

void ecs_trigger_fini(
    ecs_world_t *world,
    ecs_trigger_t *trigger)
{
    unregister_trigger(world, trigger);
    ecs_term_fini(&trigger->term);
    ecs_sparse_remove(world->triggers, trigger->id);
}

int8_t ecs_to_i8(
    int64_t v)
{
    ecs_assert(v < INT8_MAX, ECS_INTERNAL_ERROR, NULL);
    return (int8_t)v;
}

int16_t ecs_to_i16(
    int64_t v)
{
    ecs_assert(v < INT16_MAX, ECS_INTERNAL_ERROR, NULL);
    return (int16_t)v;
}

uint32_t ecs_to_u32(
    uint64_t v)
{
    ecs_assert(v < UINT32_MAX, ECS_INTERNAL_ERROR, NULL);
    return (uint32_t)v;    
}

size_t ecs_to_size_t(
    int64_t size)
{
    ecs_assert(size >= 0, ECS_INTERNAL_ERROR, NULL);
    return (size_t)size;
}

ecs_size_t ecs_from_size_t(
    size_t size)
{
   ecs_assert(size < INT32_MAX, ECS_INTERNAL_ERROR, NULL); 
   return (ecs_size_t)size;
}

int32_t ecs_next_pow_of_2(
    int32_t n)
{
    n --;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n ++;

    return n;
}

/** Convert time to double */
double ecs_time_to_double(
    ecs_time_t t)
{
    double result;
    result = t.sec;
    return result + (double)t.nanosec / (double)1000000000;
}

ecs_time_t ecs_time_sub(
    ecs_time_t t1,
    ecs_time_t t2)
{
    ecs_time_t result;

    if (t1.nanosec >= t2.nanosec) {
        result.nanosec = t1.nanosec - t2.nanosec;
        result.sec = t1.sec - t2.sec;
    } else {
        result.nanosec = t1.nanosec - t2.nanosec + 1000000000;
        result.sec = t1.sec - t2.sec - 1;
    }

    return result;
}

void ecs_sleepf(
    double t)
{
    if (t > 0) {
        int sec = (int)t;
        int nsec = (int)((t - sec) * 1000000000);
        ecs_os_sleep(sec, nsec);
    }
}

double ecs_time_measure(
    ecs_time_t *start)
{
    ecs_time_t stop, temp;
    ecs_os_get_time(&stop);
    temp = stop;
    stop = ecs_time_sub(stop, *start);
    *start = temp;
    return ecs_time_to_double(stop);
}

void* ecs_os_memdup(
    const void *src, 
    ecs_size_t size) 
{
    if (!src) {
        return NULL;
    }
    
    void *dst = ecs_os_malloc(size);
    ecs_assert(dst != NULL, ECS_OUT_OF_MEMORY, NULL);
    ecs_os_memcpy(dst, src, size);  
    return dst;  
}

int ecs_entity_compare(
    ecs_entity_t e1, 
    const void *ptr1, 
    ecs_entity_t e2, 
    const void *ptr2) 
{
    (void)ptr1;
    (void)ptr2;
    return (e1 > e2) - (e1 < e2);
}

int ecs_entity_compare_qsort(
    const void *e1,
    const void *e2)
{
    ecs_entity_t v1 = *(ecs_entity_t*)e1;
    ecs_entity_t v2 = *(ecs_entity_t*)e2;
    return ecs_entity_compare(v1, NULL, v2, NULL);
}

/*
    This code was taken from sokol_time.h 
    
    zlib/libpng license
    Copyright (c) 2018 Andre Weissflog
    This software is provided 'as-is', without any express or implied warranty.
    In no event will the authors be held liable for any damages arising from the
    use of this software.
    Permission is granted to anyone to use this software for any purpose,
    including commercial applications, and to alter it and redistribute it
    freely, subject to the following restrictions:
        1. The origin of this software must not be misrepresented; you must not
        claim that you wrote the original software. If you use this software in a
        product, an acknowledgment in the product documentation would be
        appreciated but is not required.
        2. Altered source versions must be plainly marked as such, and must not
        be misrepresented as being the original software.
        3. This notice may not be removed or altered from any source
        distribution.
*/


static int ecs_os_time_initialized;

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
static double _ecs_os_time_win_freq;
static LARGE_INTEGER _ecs_os_time_win_start;
#elif defined(__APPLE__) && defined(__MACH__)
#include <mach/mach_time.h>
static mach_timebase_info_data_t _ecs_os_time_osx_timebase;
static uint64_t _ecs_os_time_osx_start;
#else /* anything else, this will need more care for non-Linux platforms */
#include <time.h>
static uint64_t _ecs_os_time_posix_start;
#endif

/* prevent 64-bit overflow when computing relative timestamp
    see https://gist.github.com/jspohr/3dc4f00033d79ec5bdaf67bc46c813e3
*/
#if defined(_WIN32) || (defined(__APPLE__) && defined(__MACH__))
int64_t int64_muldiv(int64_t value, int64_t numer, int64_t denom) {
    int64_t q = value / denom;
    int64_t r = value % denom;
    return q * numer + r * numer / denom;
}
#endif

void ecs_os_time_setup(void) {
    if ( ecs_os_time_initialized) {
        return;
    }
    
    ecs_os_time_initialized = 1;
    #if defined(_WIN32)
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&_ecs_os_time_win_start);
        _ecs_os_time_win_freq = (double)freq.QuadPart / 1000000000.0;
    #elif defined(__APPLE__) && defined(__MACH__)
        mach_timebase_info(&_ecs_os_time_osx_timebase);
        _ecs_os_time_osx_start = mach_absolute_time();
    #else
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        _ecs_os_time_posix_start = (uint64_t)ts.tv_sec*1000000000 + (uint64_t)ts.tv_nsec; 
    #endif
}

uint64_t ecs_os_time_now(void) {
    ecs_assert(ecs_os_time_initialized != 0, ECS_INTERNAL_ERROR, NULL);

    uint64_t now;

    #if defined(_WIN32)
        LARGE_INTEGER qpc_t;
        QueryPerformanceCounter(&qpc_t);
        now = (uint64_t)(qpc_t.QuadPart / _ecs_os_time_win_freq);
    #elif defined(__APPLE__) && defined(__MACH__)
        now = (uint64_t) int64_muldiv((int64_t)mach_absolute_time(), (int64_t)_ecs_os_time_osx_timebase.numer, (int64_t)_ecs_os_time_osx_timebase.denom);
    #else
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        now = ((uint64_t)ts.tv_sec * 1000000000 + (uint64_t)ts.tv_nsec);
    #endif

    return now;
}

void ecs_os_time_sleep(
    int32_t sec, 
    int32_t nanosec) 
{
#ifndef _WIN32
    struct timespec sleepTime;
    ecs_assert(sec >= 0, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(nanosec >= 0, ECS_INTERNAL_ERROR, NULL);

    sleepTime.tv_sec = sec;
    sleepTime.tv_nsec = nanosec;
    if (nanosleep(&sleepTime, NULL)) {
        ecs_os_err("nanosleep failed");
    }
#else
    HANDLE timer;
    LARGE_INTEGER ft;

    ft.QuadPart = -((int64_t)sec * 10000000 + (int64_t)nanosec / 100);

    timer = CreateWaitableTimer(NULL, TRUE, NULL);
    SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0);
    WaitForSingleObject(timer, INFINITE);
    CloseHandle(timer);
#endif
}


#if defined(_WIN32)

static ULONG win32_current_resolution;

void ecs_increase_timer_resolution(bool enable)
{
    HMODULE hntdll = GetModuleHandle((LPCTSTR)"ntdll.dll");
    if (!hntdll) {
        return;
    }

    LONG (__stdcall *pNtSetTimerResolution)(
        ULONG desired, BOOLEAN set, ULONG * current);

    pNtSetTimerResolution = (LONG(__stdcall*)(ULONG, BOOLEAN, ULONG*))
        GetProcAddress(hntdll, "NtSetTimerResolution");

    if(!pNtSetTimerResolution) {
        return;
    }

    ULONG current, resolution = 10000; /* 1 ms */

    if (!enable && win32_current_resolution) {
        pNtSetTimerResolution(win32_current_resolution, 0, &current);
        win32_current_resolution = 0;
        return;
    } else if (!enable) {
        return;
    }

    if (resolution == win32_current_resolution) {
        return;
    }

    if (win32_current_resolution) {
        pNtSetTimerResolution(win32_current_resolution, 0, &current);
    }

    if (pNtSetTimerResolution(resolution, 1, &current)) {
        /* Try setting a lower resolution */
        resolution *= 2;
        if(pNtSetTimerResolution(resolution, 1, &current)) return;
    }

    win32_current_resolution = resolution;
}

#else
void ecs_increase_timer_resolution(bool enable)
{
    (void)enable;
    return;
}
#endif

#ifdef FLECS_PIPELINE


/* Worker thread */
static
void* worker(void *arg) {
    ecs_stage_t *stage = arg;
    ecs_world_t *world = stage->world;

    /* Start worker thread, increase counter so main thread knows how many
     * workers are ready */
    ecs_os_mutex_lock(world->sync_mutex);
    world->workers_running ++;

    if (!world->quit_workers) {
        ecs_os_cond_wait(world->worker_cond, world->sync_mutex);
    }

    ecs_os_mutex_unlock(world->sync_mutex);

    while (!world->quit_workers) {
        ecs_entity_t old_scope = ecs_set_scope((ecs_world_t*)stage, 0);

        ecs_pipeline_run(
            (ecs_world_t*)stage, 
            world->pipeline, 
            world->stats.delta_time);

        ecs_set_scope((ecs_world_t*)stage, old_scope);
    }

    ecs_os_mutex_lock(world->sync_mutex);
    world->workers_running --;
    ecs_os_mutex_unlock(world->sync_mutex);

    return NULL;
}

/* Start threads */
static
void start_workers(
    ecs_world_t *world,
    int32_t threads)
{
    ecs_set_stages(world, threads);

    ecs_assert(ecs_get_stage_count(world) == threads, ECS_INTERNAL_ERROR, NULL);

    int32_t i;
    for (i = 0; i < threads; i ++) {
        ecs_stage_t *stage = (ecs_stage_t*)ecs_get_stage(world, i);
        ecs_assert(stage != NULL, ECS_INTERNAL_ERROR, NULL);
        ecs_assert(stage->magic == ECS_STAGE_MAGIC, ECS_INTERNAL_ERROR, NULL);

        ecs_vector_get(world->worker_stages, ecs_stage_t, i);
        stage->thread = ecs_os_thread_new(worker, stage);
        ecs_assert(stage->thread != 0, ECS_THREAD_ERROR, NULL);
    }
}

/* Wait until all workers are running */
static
void wait_for_workers(
    ecs_world_t *world)
{
    int32_t stage_count = ecs_get_stage_count(world);
    bool wait = true;

    do {
        ecs_os_mutex_lock(world->sync_mutex);
        if (world->workers_running == stage_count) {
            wait = false;
        }
        ecs_os_mutex_unlock(world->sync_mutex);
    } while (wait);
}

/* Synchronize worker threads */
static
void sync_worker(
    ecs_world_t *world)
{
    int32_t stage_count = ecs_get_stage_count(world);

    /* Signal that thread is waiting */
    ecs_os_mutex_lock(world->sync_mutex);
    if (++ world->workers_waiting == stage_count) {
        /* Only signal main thread when all threads are waiting */
        ecs_os_cond_signal(world->sync_cond);
    }

    /* Wait until main thread signals that thread can continue */
    ecs_os_cond_wait(world->worker_cond, world->sync_mutex);
    ecs_os_mutex_unlock(world->sync_mutex);
}

/* Wait until all threads are waiting on sync point */
static
void wait_for_sync(
    ecs_world_t *world)
{
    int32_t stage_count = ecs_get_stage_count(world);

    ecs_os_mutex_lock(world->sync_mutex);
    if (world->workers_waiting != stage_count) {
        ecs_os_cond_wait(world->sync_cond, world->sync_mutex);
    }
    
    /* We should have been signalled unless all workers are waiting on sync */
    ecs_assert(world->workers_waiting == stage_count, 
        ECS_INTERNAL_ERROR, NULL);

    ecs_os_mutex_unlock(world->sync_mutex);
}

/* Signal workers that they can start/resume work */
static
void signal_workers(
    ecs_world_t *world)
{
    ecs_os_mutex_lock(world->sync_mutex);
    ecs_os_cond_broadcast(world->worker_cond);
    ecs_os_mutex_unlock(world->sync_mutex);
}

/** Stop worker threads */
static
bool ecs_stop_threads(
    ecs_world_t *world)
{
    bool threads_active = false;

    /* Test if threads are created. Cannot use workers_running, since this is
     * a potential race if threads haven't spun up yet. */
    ecs_vector_each(world->worker_stages, ecs_stage_t, stage, {
        if (stage->thread) {
            threads_active = true;
            break;
        }
        stage->thread = 0;
    });

    /* If no threads are active, just return */
    if (!threads_active) {
        return false;
    }

    /* Make sure all threads are running, to ensure they catch the signal */
    wait_for_workers(world);

    /* Signal threads should quit */
    world->quit_workers = true;
    signal_workers(world);

    /* Join all threads with main */
    ecs_vector_each(world->worker_stages, ecs_stage_t, stage, {
        ecs_os_thread_join(stage->thread);
        stage->thread = 0;
    });

    world->quit_workers = false;
    ecs_assert(world->workers_running == 0, ECS_INTERNAL_ERROR, NULL);

    /* Deinitialize stages */
    ecs_set_stages(world, 0);

    return true;
}

/* -- Private functions -- */

void ecs_worker_begin(
    ecs_world_t *world)
{
    ecs_stage_from_world(&world);
    int32_t stage_count = ecs_get_stage_count(world);
    ecs_assert(stage_count != 0, ECS_INTERNAL_ERROR, NULL);
    
    if (stage_count == 1) {
        ecs_staging_begin(world);
    }
}

bool ecs_worker_sync(
    ecs_world_t *world)
{
    ecs_stage_from_world(&world);

    int32_t build_count = world->stats.pipeline_build_count_total;
    int32_t stage_count = ecs_get_stage_count(world);
    ecs_assert(stage_count != 0, ECS_INTERNAL_ERROR, NULL);

    /* If there are no threads, merge in place */
    if (stage_count == 1) {
        ecs_staging_end(world);
        ecs_pipeline_update(world, world->pipeline, false);
        ecs_staging_begin(world);

    /* Synchronize all workers. The last worker to reach the sync point will
     * signal the main thread, which will perform the merge. */
    } else {
        sync_worker(world);
    }

    return world->stats.pipeline_build_count_total != build_count;
}

void ecs_worker_end(
    ecs_world_t *world)
{
    ecs_stage_from_world(&world);

    int32_t stage_count = ecs_get_stage_count(world);
    ecs_assert(stage_count != 0, ECS_INTERNAL_ERROR, NULL);

    /* If there are no threads, merge in place */
    if (stage_count == 1) {
        ecs_staging_end(world);

    /* Synchronize all workers. The last worker to reach the sync point will
     * signal the main thread, which will perform the merge. */
    } else {
        sync_worker(world);
    }
}

void ecs_workers_progress(
    ecs_world_t *world,
    ecs_entity_t pipeline,
    FLECS_FLOAT delta_time)
{
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);
    int32_t stage_count = ecs_get_stage_count(world);

    ecs_time_t start = {0};
    if (world->measure_frame_time) {
        ecs_time_measure(&start);
    }

    if (stage_count == 1) {
        ecs_pipeline_update(world, pipeline, true);
        ecs_entity_t old_scope = ecs_set_scope(world, 0);
        ecs_world_t *stage = ecs_get_stage(world, 0);

        ecs_pipeline_run(stage, pipeline, delta_time);
        ecs_set_scope(world, old_scope);
    } else {
        int32_t i, sync_count = ecs_pipeline_update(world, pipeline, true);

        /* Make sure workers are running and ready */
        wait_for_workers(world);

        /* Synchronize n times for each op in the pipeline */
        for (i = 0; i < sync_count; i ++) {
            ecs_staging_begin(world);

            /* Signal workers that they should start running systems */
            world->workers_waiting = 0;
            signal_workers(world);

            /* Wait until all workers are waiting on sync point */
            wait_for_sync(world);

            /* Merge */
            ecs_staging_end(world);

            int32_t update_count;
            if ((update_count = ecs_pipeline_update(world, pipeline, false))) {
                /* The number of operations in the pipeline could have changed
                 * as result of the merge */
                sync_count = update_count;
            }
        }
    }

    if (world->measure_frame_time) {
        world->stats.system_time_total += (FLECS_FLOAT)ecs_time_measure(&start);
    }    
}


/* -- Public functions -- */

void ecs_set_threads(
    ecs_world_t *world,
    int32_t threads)
{
    ecs_assert(threads <= 1 || ecs_os_has_threading(), ECS_MISSING_OS_API, NULL);

    int32_t stage_count = ecs_get_stage_count(world);

    if (!world->arg_threads && stage_count != threads) {
        /* Stop existing threads */
        if (stage_count > 1) {
            if (ecs_stop_threads(world)) {
                ecs_os_cond_free(world->worker_cond);
                ecs_os_cond_free(world->sync_cond);
                ecs_os_mutex_free(world->sync_mutex);
            }
        }

        /* Start threads if number of threads > 1 */
        if (threads > 1) {
            world->worker_cond = ecs_os_cond_new();
            world->sync_cond = ecs_os_cond_new();
            world->sync_mutex = ecs_os_mutex_new();
            start_workers(world, threads);
        }

        /* Iterate tables, make sure the ecs_data_t arrays are large enough */
        ecs_sparse_each(world->store.tables, ecs_table_t, table, {
            ecs_table_get_data(table);
        });
    }
}

#endif

#ifdef FLECS_PIPELINE


ECS_TYPE_DECL(EcsPipelineQuery);

static ECS_CTOR(EcsPipelineQuery, ptr, {
    memset(ptr, 0, _size);
})

static ECS_DTOR(EcsPipelineQuery, ptr, {
    ecs_vector_free(ptr->ops);
})

static
int compare_entity(
    ecs_entity_t e1, 
    const void *ptr1, 
    ecs_entity_t e2, 
    const void *ptr2) 
{
    (void)ptr1;
    (void)ptr2;
    return (e1 > e2) - (e1 < e2);
}

static
int rank_phase(
    ecs_world_t *world,
    ecs_entity_t rank_component,
    ecs_type_t type) 
{
    const EcsType *pipeline_type = ecs_get(world, rank_component, EcsType);
    ecs_assert(pipeline_type != NULL, ECS_INTERNAL_ERROR, NULL);

    /* Find tag in system that belongs to pipeline */
    ecs_entity_t *sys_comps = ecs_vector_first(type, ecs_entity_t);
    int32_t c, t, count = ecs_vector_count(type);

    ecs_entity_t *tags = ecs_vector_first(pipeline_type->normalized, ecs_entity_t);
    int32_t tag_count = ecs_vector_count(pipeline_type->normalized);

    ecs_entity_t result = 0;

    for (c = 0; c < count; c ++) {
        ecs_entity_t comp = sys_comps[c];
        for (t = 0; t < tag_count; t ++) {
            if (comp == tags[t]) {
                result = comp;
                break;
            }
        }
        if (result) {
            break;
        }
    }

    ecs_assert(result != 0, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(result < INT_MAX, ECS_INTERNAL_ERROR, NULL);

    return (int)result;
}

typedef enum ComponentWriteState {
    NotWritten = 0,
    WriteToMain,
    WriteToStage
} ComponentWriteState;

typedef struct write_state_t {
    ecs_map_t *components;
    bool wildcard;
} write_state_t;

static
int32_t get_write_state(
    ecs_map_t *write_state,
    ecs_entity_t component)
{
    int32_t *ptr = ecs_map_get(write_state, int32_t, component);
    if (ptr) {
        return *ptr;
    } else {
        return 0;
    }
}

static
void set_write_state(
    write_state_t *write_state,
    ecs_entity_t component,
    int32_t value)
{
    if (component == EcsWildcard) {
        ecs_assert(value == WriteToStage, ECS_INTERNAL_ERROR, NULL);
        write_state->wildcard = true;
    } else {
        ecs_map_set(write_state->components, component, &value);
    }
}

static
void reset_write_state(
    write_state_t *write_state)
{
    ecs_map_clear(write_state->components);
    write_state->wildcard = false;
}

static
int32_t get_any_write_state(
    write_state_t *write_state)
{
    if (write_state->wildcard) {
        return WriteToStage;
    }

    ecs_map_iter_t it = ecs_map_iter(write_state->components);
    int32_t *elem;
    while ((elem = ecs_map_next(&it, int32_t, NULL))) {
        if (*elem == WriteToStage) {
            return WriteToStage;
        }
    }

    return 0;
}

static
bool check_term_component(
    ecs_term_t *term,
    bool is_active,
    ecs_entity_t component,
    write_state_t *write_state)    
{
    int32_t state = get_write_state(write_state->components, component);

    ecs_term_id_t *subj = &term->args[0];

    if ((subj->set & EcsSelf) && subj->entity == EcsThis && term->oper != EcsNot) {
        switch(term->inout) {
        case EcsInOutDefault:
        case EcsInOut:
        case EcsIn:
            if (state == WriteToStage || write_state->wildcard) {
                return true;
            }
            // fall through
        case EcsOut:
            if (is_active && term->inout != EcsIn) {
                set_write_state(write_state, component, WriteToMain);
            }
        };
    } else if (!subj->entity || term->oper == EcsNot) {
        bool needs_merge = false;

        switch(term->inout) {
        case EcsInOutDefault:
        case EcsIn:
        case EcsInOut:
            if (state == WriteToStage) {
                needs_merge = true;
            }
            if (component == EcsWildcard) {
                if (get_any_write_state(write_state) == WriteToStage) {
                    needs_merge = true;
                }
            }
            break;
        default:
            break;
        };

        switch(term->inout) {
        case EcsInOutDefault:
            if (!(subj->set & EcsSelf) || !subj->entity || subj->entity != EcsThis) {
                break;
            }
            // fall through
        case EcsInOut:
        case EcsOut:
            if (is_active) {
                set_write_state(write_state, component, WriteToStage);
            }
            break;
        default:
            break;
        };   

        if (needs_merge) {
            return true;
        }
    }

    return false;
}

static
bool check_term(
    ecs_term_t *term,
    bool is_active,
    write_state_t *write_state)
{
    if (term->oper != EcsOr) {
        return check_term_component(
            term, is_active, term->id, write_state);
    }  

    return false;
}

static
bool build_pipeline(
    ecs_world_t *world,
    ecs_entity_t pipeline,
    EcsPipelineQuery *pq)
{
    (void)pipeline;

    ecs_query_iter(pq->query);

    if (pq->match_count == pq->query->match_count) {
        /* No need to rebuild the pipeline */
        return false;
    }

    ecs_trace_2("rebuilding pipeline #[green]%s", 
        ecs_get_name(world, pipeline));

    world->stats.pipeline_build_count_total ++;

    write_state_t ws = {
        .components = ecs_map_new(int32_t, ECS_HI_COMPONENT_ID),
        .wildcard = false
    };

    ecs_pipeline_op_t *op = NULL;
    ecs_vector_t *ops = NULL;
    ecs_query_t *query = pq->build_query;

    if (pq->ops) {
        ecs_vector_free(pq->ops);
    }

    /* Iterate systems in pipeline, add ops for running / merging */
    ecs_iter_t it = ecs_query_iter(query);
    while (ecs_query_next(&it)) {
        EcsSystem *sys = ecs_term(&it, EcsSystem, 1);

        int i;
        for (i = 0; i < it.count; i ++) {      
            ecs_query_t *q = sys[i].query;
            if (!q) {
                continue;
            }

            bool needs_merge = false;
            bool is_active = !ecs_has_id(
                world, it.entities[i], EcsInactive);
            
            ecs_term_t *terms = q->filter.terms;
            int32_t t, term_count = q->filter.term_count;
            for (t = 0; t < term_count; t ++) {
                needs_merge |= check_term(&terms[t], is_active, &ws);
            }

            if (needs_merge) {
                /* After merge all components will be merged, so reset state */
                reset_write_state(&ws);
                op = NULL;

                /* Re-evaluate columns to set write flags if system is active.
                 * If system is inactive, it can't write anything and so it
                 * should not insert unnecessary merges.  */
                needs_merge = false;
                if (is_active) {
                    for (t = 0; t < term_count; t ++) {
                        needs_merge |= check_term(&terms[t], true, &ws);
                    }
                }

                /* The component states were just reset, so if we conclude that
                 * another merge is needed something is wrong. */
                ecs_assert(needs_merge == false, ECS_INTERNAL_ERROR, NULL);        
            }

            if (!op) {
                op = ecs_vector_add(&ops, ecs_pipeline_op_t);
                op->count = 0;
            }

            /* Don't increase count for inactive systems, as they are ignored by
             * the query used to run the pipeline. */
            if (is_active) {
                op->count ++;
            }
        }
    }

    ecs_map_free(ws.components);

    /* Force sort of query as this could increase the match_count */
    pq->match_count = pq->query->match_count;
    pq->ops = ops;

    return true;
}

static
int32_t iter_reset(
    const EcsPipelineQuery *pq,
    ecs_iter_t *iter_out,
    ecs_pipeline_op_t **op_out,
    ecs_entity_t move_to)
{
    ecs_pipeline_op_t *op = ecs_vector_first(pq->ops, ecs_pipeline_op_t);
    int32_t ran_since_merge = 0;

    ecs_iter_t it = ecs_query_iter(pq->query);
    while (ecs_query_next(&it)) {
        int32_t i;
        for(i = 0; i < it.count; i ++) {
            ecs_entity_t e = it.entities[i];

            ran_since_merge ++;
            if (ran_since_merge == op->count) {
                ran_since_merge = 0;
                op ++;
            }

            if (e == move_to) {
                *iter_out = it;
                *op_out = op;
                return i;
            }
        }
    }

    ecs_abort(ECS_UNSUPPORTED, NULL);

    return -1;
}

int32_t ecs_pipeline_update(
    ecs_world_t *world,
    ecs_entity_t pipeline,
    bool start_of_frame)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(!world->is_readonly, ECS_INVALID_OPERATION, NULL);
    ecs_assert(pipeline != 0, ECS_INTERNAL_ERROR, NULL);

    /* If any entity mutations happened that could have affected query matching
     * notify appropriate queries so caches are up to date. This includes the
     * pipeline query. */
    if (start_of_frame) {
        ecs_eval_component_monitors(world);
    }

    bool added = false;
    EcsPipelineQuery *pq = ecs_get_mut(world, pipeline, EcsPipelineQuery, &added);
    ecs_assert(added == false, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(pq != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(pq->query != NULL, ECS_INTERNAL_ERROR, NULL);

    build_pipeline(world, pipeline, pq);

    return ecs_vector_count(pq->ops);
}

void ecs_pipeline_run(
    ecs_world_t *world,
    ecs_entity_t pipeline,
    FLECS_FLOAT delta_time)
{
    ecs_assert(world != NULL, ECS_INVALID_OPERATION, NULL);

    if (!pipeline) {
        pipeline = world->pipeline;
    }    

    /* If the world is passed to ecs_pipeline_run, the function will take care
     * of staging, so the world should not be in staged mode when called. */
    if (world->magic == ECS_WORLD_MAGIC) {
        ecs_assert(!world->is_readonly, ECS_INVALID_OPERATION, NULL);

        /* Forward to worker_progress. This function handles staging, threading
         * and synchronization across workers. */
        ecs_workers_progress(world, pipeline, delta_time);
        return;

    /* If a stage is passed, the function could be ran from a worker thread. In
     * that case the main thread should manage staging, and staging should be
     * enabled. */
    } else {
        ecs_assert(world->magic == ECS_STAGE_MAGIC, ECS_INVALID_PARAMETER, NULL);
    }

    ecs_stage_t *stage = ecs_stage_from_world(&world);  
    
    const EcsPipelineQuery *pq = ecs_get(world, pipeline, EcsPipelineQuery);
    ecs_assert(pq != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(pq->query != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_vector_t *ops = pq->ops;
    ecs_pipeline_op_t *op = ecs_vector_first(ops, ecs_pipeline_op_t);
    ecs_pipeline_op_t *op_last = ecs_vector_last(ops, ecs_pipeline_op_t);
    int32_t ran_since_merge = 0;

    int32_t stage_index = ecs_get_stage_id(stage->thread_ctx);
    int32_t stage_count = ecs_get_stage_count(world);

    ecs_worker_begin(stage->thread_ctx);
    
    ecs_iter_t it = ecs_query_iter(pq->query);
    while (ecs_query_next(&it)) {
        EcsSystem *sys = ecs_term(&it, EcsSystem, 1);

        int32_t i;
        for(i = 0; i < it.count; i ++) {
            ecs_entity_t e = it.entities[i];

            ecs_run_intern(world, stage, e, &sys[i], stage_index, stage_count, 
                delta_time, 0, 0, NULL, NULL);

            ran_since_merge ++;
            world->stats.systems_ran_frame ++;

            if (op != op_last && ran_since_merge == op->count) {
                ran_since_merge = 0;
                op++;

                /* If the set of matched systems changed as a result of the
                 * merge, we have to reset the iterator and move it to our
                 * current position (system). If there are a lot of systems
                 * in the pipeline this can be an expensive operation, but
                 * should happen infrequently. */
                if (ecs_worker_sync(stage->thread_ctx)) {
                    i = iter_reset(pq, &it, &op, e);
                    op_last = ecs_vector_last(pq->ops, ecs_pipeline_op_t);
                    sys = ecs_term(&it, EcsSystem, 1);
                }
            }
        }
    }

    ecs_worker_end(stage->thread_ctx);
}

static
void add_pipeline_tags_to_sig(
    ecs_world_t *world,
    ecs_term_t *terms,
    ecs_type_t type)
{
    (void)world;
    
    int32_t i, count = ecs_vector_count(type);
    ecs_entity_t *entities = ecs_vector_first(type, ecs_entity_t);

    for (i = 0; i < count; i ++) {
        terms[i] = (ecs_term_t){
            .inout = EcsIn,
            .oper = EcsOr,
            .pred.entity = entities[i],
            .args[0] = {
                .entity = EcsThis,
                .set = EcsSelf | EcsSuperSet
            }
        };
    }
}

static
ecs_query_t* build_pipeline_query(
    ecs_world_t *world,
    ecs_entity_t pipeline,
    const char *name,
    bool with_inactive)
{
    const EcsType *type_ptr = ecs_get(world, pipeline, EcsType);
    ecs_assert(type_ptr != NULL, ECS_INTERNAL_ERROR, NULL);

    int32_t type_count = ecs_vector_count(type_ptr->normalized);
    int32_t term_count = 2;

    if (with_inactive) {
        term_count ++;
    }

    ecs_term_t *terms = ecs_os_malloc(
        (type_count + term_count) * ECS_SIZEOF(ecs_term_t));

    terms[0] = (ecs_term_t){
        .inout = EcsIn,
        .oper = EcsAnd,
        .pred.entity = ecs_id(EcsSystem),
        .args[0] = {
            .entity = EcsThis,
            .set = EcsSelf | EcsSuperSet
        }
    };

    terms[1] = (ecs_term_t){
        .inout = EcsIn,
        .oper = EcsNot,
        .pred.entity = EcsDisabledIntern,
        .args[0] = {
            .entity = EcsThis,
            .set = EcsSelf | EcsSuperSet
        }
    };

    if (with_inactive) {
        terms[2] = (ecs_term_t){
            .inout = EcsIn,
            .oper = EcsNot,
            .pred.entity = EcsInactive,
            .args[0] = {
                .entity = EcsThis,
                .set = EcsSelf | EcsSuperSet
            }
        };
    }

    add_pipeline_tags_to_sig(world, &terms[term_count], type_ptr->normalized);    

    ecs_query_t *result = ecs_query_init(world, &(ecs_query_desc_t){
        .filter = {
            .name = name,
            .terms_buffer = terms,
            .terms_buffer_count = term_count + type_count
        },
        .order_by = compare_entity,
        .group_by = rank_phase,
        .group_by_id = pipeline
    });

    ecs_assert(result != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_os_free(terms);

    return result;
}

static 
void EcsOnAddPipeline(
    ecs_iter_t *it)
{
    ecs_world_t *world = it->world;
    ecs_entity_t *entities = it->entities;

    int32_t i;
    for (i = it->count - 1; i >= 0; i --) {
        ecs_entity_t pipeline = entities[i];
        
#ifndef NDEBUG
        ecs_trace_1("pipeline #[green]%s#[normal] created",
            ecs_get_name(world, pipeline));
#endif
        ecs_log_push();

        /* Build signature for pipeline quey that matches EcsSystems, has the
         * pipeline phases as OR columns, and ignores systems with EcsInactive 
         * and EcsDisabledIntern. Note that EcsDisabled is automatically ignored 
         * by the regular query matching */
        ecs_query_t *query = build_pipeline_query(
            world, pipeline, "BuiltinPipelineQuery", true);
        ecs_assert(query != NULL, ECS_INTERNAL_ERROR, NULL);

        /* Build signature for pipeline build query. The build query includes
         * systems that are inactive, as an inactive system may become active as
         * a result of another system, and as a result the correct merge 
         * operations need to be put in place. */
        ecs_query_t *build_query = build_pipeline_query(
            world, pipeline, "BuiltinPipelineBuildQuery", false);
        ecs_assert(build_query != NULL, ECS_INTERNAL_ERROR, NULL);

        EcsPipelineQuery *pq = ecs_get_mut(
            world, pipeline, EcsPipelineQuery, NULL);
        ecs_assert(pq != NULL, ECS_INTERNAL_ERROR, NULL);

        pq->query = query;
        pq->build_query = build_query;
        pq->match_count = -1;
        pq->ops = NULL;

        ecs_log_pop();
    }
}

/* -- Public API -- */

bool ecs_progress(
    ecs_world_t *world,
    FLECS_FLOAT user_delta_time)
{
    float delta_time = ecs_frame_begin(world, user_delta_time);

    ecs_pipeline_run(world, 0, delta_time);

    ecs_frame_end(world);

    return !world->should_quit;
}

void ecs_set_time_scale(
    ecs_world_t *world,
    FLECS_FLOAT scale)
{
    world->stats.time_scale = scale;
}

void ecs_reset_clock(
    ecs_world_t *world)
{
    world->stats.world_time_total = 0;
    world->stats.world_time_total_raw = 0;
}

void ecs_deactivate_systems(
    ecs_world_t *world)
{
    ecs_assert(!world->is_readonly, ECS_INVALID_WHILE_ITERATING, NULL);

    ecs_entity_t pipeline = world->pipeline;
    const EcsPipelineQuery *pq = ecs_get( world, pipeline, EcsPipelineQuery);
    ecs_assert(pq != NULL, ECS_INTERNAL_ERROR, NULL);

    /* Iterate over all systems, add EcsInvalid tag if queries aren't matched
     * with any tables */
    ecs_iter_t it = ecs_query_iter(pq->build_query);

    /* Make sure that we defer adding the inactive tags until after iterating
     * the query */
    ecs_defer_none(world, &world->stage);

    while( ecs_query_next(&it)) {
        EcsSystem *sys = ecs_term(&it, EcsSystem, 1);

        int32_t i;
        for (i = 0; i < it.count; i ++) {
            ecs_query_t *query = sys[i].query;
            if (query) {
                if (!ecs_vector_count(query->tables)) {
                    ecs_add_id(world, it.entities[i], EcsInactive);
                }
            }
        }
    }

    ecs_defer_flush(world, &world->stage);
}

void ecs_set_pipeline(
    ecs_world_t *world,
    ecs_entity_t pipeline)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_PARAMETER, NULL);
    ecs_assert( ecs_get(world, pipeline, EcsPipelineQuery) != NULL, 
        ECS_INVALID_PARAMETER, NULL);

    world->pipeline = pipeline;
}

ecs_entity_t ecs_get_pipeline(
    const ecs_world_t *world)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    world = ecs_get_world(world);
    return world->pipeline;
}

/* -- Module implementation -- */

static
void FlecsPipelineFini(
    ecs_world_t *world,
    void *ctx)
{
    (void)ctx;
    if (ecs_get_stage_count(world)) {
        ecs_set_threads(world, 0);
    }
}

void FlecsPipelineImport(
    ecs_world_t *world)
{
    ECS_MODULE(world, FlecsPipeline);

    ECS_IMPORT(world, FlecsSystem);

    ecs_set_name_prefix(world, "Ecs");

    ecs_bootstrap_tag(world, EcsPipeline);
    ecs_bootstrap_component(world, EcsPipelineQuery);

    /* Phases of the builtin pipeline are regular entities. Names are set so
     * they can be resolved by type expressions. */
    ecs_bootstrap_tag(world, EcsPreFrame);
    ecs_bootstrap_tag(world, EcsOnLoad);
    ecs_bootstrap_tag(world, EcsPostLoad);
    ecs_bootstrap_tag(world, EcsPreUpdate);
    ecs_bootstrap_tag(world, EcsOnUpdate);
    ecs_bootstrap_tag(world, EcsOnValidate);
    ecs_bootstrap_tag(world, EcsPostUpdate);
    ecs_bootstrap_tag(world, EcsPreStore);
    ecs_bootstrap_tag(world, EcsOnStore);
    ecs_bootstrap_tag(world, EcsPostFrame);

    ECS_TYPE_IMPL(EcsPipelineQuery);

    /* Set ctor and dtor for PipelineQuery */
    ecs_set(world, ecs_id(EcsPipelineQuery), EcsComponentLifecycle, {
        .ctor = ecs_ctor(EcsPipelineQuery),
        .dtor = ecs_dtor(EcsPipelineQuery)
    });

    /* When the Pipeline tag is added a pipeline will be created */
    ECS_SYSTEM(world, EcsOnAddPipeline, EcsOnSet, Pipeline, Type);

    /* Create the builtin pipeline */
    world->pipeline = ecs_type_init(world, &(ecs_type_desc_t){
        .entity = {
            .name = "BuiltinPipeline",
            .add = {EcsPipeline}
        },
        .ids = {
            EcsPreFrame, EcsOnLoad, EcsPostLoad, EcsPreUpdate, EcsOnUpdate,
            EcsOnValidate, EcsPostUpdate, EcsPreStore, EcsOnStore, EcsPostFrame
         }
    });

    /* Cleanup thread administration when world is destroyed */
    ecs_atfini(world, FlecsPipelineFini, NULL);
}

#endif

#ifdef FLECS_TIMER


ecs_type_t ecs_type(EcsTimer);
ecs_type_t ecs_type(EcsRateFilter);

static
void AddTickSource(ecs_iter_t *it) {
    int32_t i;
    for (i = 0; i < it->count; i ++) {
        ecs_set(it->world, it->entities[i], EcsTickSource, {0});
    }
}

static
void ProgressTimers(ecs_iter_t *it) {
    EcsTimer *timer = ecs_term(it, EcsTimer, 1);
    EcsTickSource *tick_source = ecs_term(it, EcsTickSource, 2);

    ecs_assert(timer != NULL, ECS_INTERNAL_ERROR, NULL);

    int i;
    for (i = 0; i < it->count; i ++) {
        tick_source[i].tick = false;

        if (!timer[i].active) {
            continue;
        }

        const ecs_world_info_t *info = ecs_get_world_info(it->world);
        FLECS_FLOAT time_elapsed = timer[i].time + info->delta_time_raw;
        FLECS_FLOAT timeout = timer[i].timeout;
        
        if (time_elapsed >= timeout) {
            FLECS_FLOAT t = time_elapsed - timeout;
            if (t > timeout) {
                t = 0;
            }

            timer[i].time = t; /* Initialize with remainder */            
            tick_source[i].tick = true;
            tick_source[i].time_elapsed = time_elapsed;

            if (timer[i].single_shot) {
                timer[i].active = false;
            }
        } else {
            timer[i].time = time_elapsed;
        }  
    }
}

static
void ProgressRateFilters(ecs_iter_t *it) {
    EcsRateFilter *filter = ecs_term(it, EcsRateFilter, 1);
    EcsTickSource *tick_dst = ecs_term(it, EcsTickSource, 2);

    int i;
    for (i = 0; i < it->count; i ++) {
        ecs_entity_t src = filter[i].src;
        bool inc = false;

        filter[i].time_elapsed += it->delta_time;

        if (src) {
            const EcsTickSource *tick_src = ecs_get(it->world, src, EcsTickSource);
            if (tick_src) {
                inc = tick_src->tick;
            } else {
                inc = true;
            }
        } else {
            inc = true;
        }

        if (inc) {
            filter[i].tick_count ++;
            bool triggered = !(filter[i].tick_count % filter[i].rate);
            tick_dst[i].tick = triggered;
            tick_dst[i].time_elapsed = filter[i].time_elapsed;

            if (triggered) {
                filter[i].time_elapsed = 0;
            }            
        } else {
            tick_dst[i].tick = false;
        }
    }
}

static
void ProgressTickSource(ecs_iter_t *it) {
    EcsTickSource *tick_src = ecs_term(it, EcsTickSource, 1);

    /* If tick source has no filters, tick unconditionally */
    int i;
    for (i = 0; i < it->count; i ++) {
        tick_src[i].tick = true;
        tick_src[i].time_elapsed = it->delta_time;
    }
}

ecs_entity_t ecs_set_timeout(
    ecs_world_t *world,
    ecs_entity_t timer,
    FLECS_FLOAT timeout)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);

    timer = ecs_set(world, timer, EcsTimer, {
        .timeout = timeout,
        .single_shot = true,
        .active = true
    });

    EcsSystem *system_data = ecs_get_mut(world, timer, EcsSystem, NULL);
    if (system_data) {
        system_data->tick_source = timer;
    }

    return timer;
}

FLECS_FLOAT ecs_get_timeout(
    const ecs_world_t *world,
    ecs_entity_t timer)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(timer != 0, ECS_INVALID_PARAMETER, NULL);

    const EcsTimer *value = ecs_get(world, timer, EcsTimer);
    if (value) {
        return value->timeout;
    } else {
        return 0;
    }
}

ecs_entity_t ecs_set_interval(
    ecs_world_t *world,
    ecs_entity_t timer,
    FLECS_FLOAT interval)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);

    timer = ecs_set(world, timer, EcsTimer, {
        .timeout = interval,
        .active = true
    });

    EcsSystem *system_data = ecs_get_mut(world, timer, EcsSystem, NULL);
    if (system_data) {
        system_data->tick_source = timer;
    }  

    return timer;  
}

FLECS_FLOAT ecs_get_interval(
    const ecs_world_t *world,
    ecs_entity_t timer)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);

    if (!timer) {
        return 0;
    }

    const EcsTimer *value = ecs_get(world, timer, EcsTimer);
    if (value) {
        return value->timeout;
    } else {
        return 0;
    }
}

void ecs_start_timer(
    ecs_world_t *world,
    ecs_entity_t timer)
{
    EcsTimer *ptr = ecs_get_mut(world, timer, EcsTimer, NULL);
    ecs_assert(ptr != NULL, ECS_INVALID_PARAMETER, NULL);

    ptr->active = true;
    ptr->time = 0;
}

void ecs_stop_timer(
    ecs_world_t *world,
    ecs_entity_t timer)
{
    EcsTimer *ptr = ecs_get_mut(world, timer, EcsTimer, NULL);
    ecs_assert(ptr != NULL, ECS_INVALID_PARAMETER, NULL);

    ptr->active = false;
}

ecs_entity_t ecs_set_rate(
    ecs_world_t *world,
    ecs_entity_t filter,
    int32_t rate,
    ecs_entity_t source)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);

    filter = ecs_set(world, filter, EcsRateFilter, {
        .rate = rate,
        .src = source
    });

    EcsSystem *system_data = ecs_get_mut(world, filter, EcsSystem, NULL);
    if (system_data) {
        system_data->tick_source = filter;
    }  

    return filter;     
}

/* Deprecated */
ecs_entity_t ecs_set_rate_filter(
    ecs_world_t *world,
    ecs_entity_t filter,
    int32_t rate,
    ecs_entity_t source)
{
    return ecs_set_rate(world, filter, rate, source);
}

void ecs_set_tick_source(
    ecs_world_t *world,
    ecs_entity_t system,
    ecs_entity_t tick_source)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(system != 0, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(tick_source != 0, ECS_INVALID_PARAMETER, NULL);

    EcsSystem *system_data = ecs_get_mut(world, system, EcsSystem, NULL);
    ecs_assert(system_data != NULL, ECS_INVALID_PARAMETER, NULL);

    system_data->tick_source = tick_source;
}

void FlecsTimerImport(
    ecs_world_t *world)
{    
    ECS_MODULE(world, FlecsTimer);

    ECS_IMPORT(world, FlecsPipeline);

    ecs_set_name_prefix(world, "Ecs");

    ecs_bootstrap_component(world, EcsTimer);
    ecs_bootstrap_component(world, EcsRateFilter);

    /* Add EcsTickSource to timers and rate filters */
    ECS_SYSTEM(world, AddTickSource, EcsPreFrame, [in] Timer || RateFilter, [out] !flecs.system.TickSource);

    /* Timer handling */
    ECS_SYSTEM(world, ProgressTimers, EcsPreFrame, Timer, flecs.system.TickSource);

    /* Rate filter handling */
    ECS_SYSTEM(world, ProgressRateFilters, EcsPreFrame, [in] RateFilter, [out] flecs.system.TickSource);

    /* TickSource without a timer or rate filter just increases each frame */
    ECS_SYSTEM(world, ProgressTickSource, EcsPreFrame, [out] flecs.system.TickSource, !RateFilter, !Timer);
}

#endif

#ifdef FLECS_SYSTEM


/* Global type variables */
ECS_TYPE_DECL(EcsComponentLifecycle);
ECS_TYPE_DECL(EcsSystem);
ECS_TYPE_DECL(EcsTickSource);
ECS_TYPE_DECL(EcsIterAction);
ECS_TYPE_DECL(EcsContext);

static
ecs_on_demand_in_t* get_in_component(
    ecs_map_t *component_map,
    ecs_entity_t component)
{
    ecs_on_demand_in_t *in = ecs_map_get(
        component_map, ecs_on_demand_in_t, component);
    if (!in) {
        ecs_on_demand_in_t in_value = {0};
        ecs_map_set(component_map, component, &in_value);
        in = ecs_map_get(component_map, ecs_on_demand_in_t, component);
        ecs_assert(in != NULL, ECS_INTERNAL_ERROR, NULL);
    }

    return in;
}

static
void activate_in_columns(
    ecs_world_t *world,
    ecs_query_t *query,
    ecs_map_t *component_map,
    bool activate)
{
    ecs_term_t *terms = query->filter.terms;
    int32_t i, count = query->filter.term_count;

    for (i = 0; i < count; i ++) {
        if (terms[i].inout == EcsIn) {
            ecs_on_demand_in_t *in = get_in_component(
                component_map, terms[i].id);
            ecs_assert(in != NULL, ECS_INTERNAL_ERROR, NULL);

            in->count += activate ? 1 : -1;

            ecs_assert(in->count >= 0, ECS_INTERNAL_ERROR, NULL);

            /* If this is the first system that registers the in component, walk
             * over all already registered systems to enable them */
            if (in->systems && 
               ((activate && in->count == 1) || 
                (!activate && !in->count))) 
            {
                ecs_on_demand_out_t **out = ecs_vector_first(
                    in->systems, ecs_on_demand_out_t*);
                int32_t s, in_count = ecs_vector_count(in->systems);

                for (s = 0; s < in_count; s ++) {
                    /* Increase the count of the system with the out params */
                    out[s]->count += activate ? 1 : -1;
                    
                    /* If this is the first out column that is requested from
                     * the OnDemand system, enable it */
                    if (activate && out[s]->count == 1) {
                        ecs_remove_id(world, out[s]->system, EcsDisabledIntern);
                    } else if (!activate && !out[s]->count) {
                        ecs_add_id(world, out[s]->system, EcsDisabledIntern);             
                    }
                }
            }
        }
    }    
}

static
void register_out_column(
    ecs_map_t *component_map,
    ecs_entity_t component,
    ecs_on_demand_out_t *on_demand_out)
{
    ecs_on_demand_in_t *in = get_in_component(component_map, component);
    ecs_assert(in != NULL, ECS_INTERNAL_ERROR, NULL);

    on_demand_out->count += in->count;
    ecs_on_demand_out_t **elem = ecs_vector_add(&in->systems, ecs_on_demand_out_t*);
    *elem = on_demand_out;
}

static
void register_out_columns(
    ecs_world_t *world,
    ecs_entity_t system,
    EcsSystem *system_data)
{
    ecs_query_t *query = system_data->query;
    ecs_term_t *terms = query->filter.terms;
    int32_t out_count = 0, i, count = query->filter.term_count;

    for (i = 0; i < count; i ++) {
        if (terms[i].inout == EcsOut) {
            if (!system_data->on_demand) {
                system_data->on_demand = ecs_os_malloc(sizeof(ecs_on_demand_out_t));
                ecs_assert(system_data->on_demand != NULL, ECS_OUT_OF_MEMORY, NULL);

                system_data->on_demand->system = system;
                system_data->on_demand->count = 0;
            }

            /* If column operator is NOT and the inout kind is [out], the system
             * explicitly states that it will create the component (it is not
             * there, yet it is an out column). In this case it doesn't make
             * sense to wait until [in] terms get activated (matched with
             * entities) since the component is not there yet. Therefore add it
             * to the on_enable_components list, so this system will be enabled
             * when a [in] column is enabled, rather than activated */
            ecs_map_t *component_map;
            if (terms[i].oper == EcsNot) {
                component_map = world->on_enable_components;
            } else {
                component_map = world->on_activate_components;
            }

            register_out_column(
                component_map, terms[i].id, 
                system_data->on_demand);

            out_count ++;
        }
    }

    /* If there are no out terms in the on-demand system, the system will
     * never be enabled */
    ecs_assert(out_count != 0, ECS_NO_OUT_COLUMNS, ecs_get_name(world, system));
}

static
void invoke_status_action(
    ecs_world_t *world,
    ecs_entity_t system,
    const EcsSystem *system_data,
    ecs_system_status_t status)
{
    ecs_system_status_action_t action = system_data->status_action;
    if (action) {
        action(world, system, status, system_data->status_ctx);
    }
}

/* Invoked when system becomes active or inactive */
void ecs_system_activate(
    ecs_world_t *world,
    ecs_entity_t system,
    bool activate,
    const EcsSystem *system_data)
{
    ecs_assert(!world->is_readonly, ECS_INTERNAL_ERROR, NULL);

    if (activate) {
        ecs_remove_id(world, system, EcsInactive);
    }

    if (!system_data) {
        system_data = ecs_get(world, system, EcsSystem);
    }
    if (!system_data || !system_data->query) {
        return;
    }

    /* If system contains in columns, signal that they are now in use */
    activate_in_columns(
        world, system_data->query, world->on_activate_components, activate);

    /* Invoke system status action */
    invoke_status_action(world, system, system_data, 
        activate ? EcsSystemActivated : EcsSystemDeactivated);

    ecs_trace_2("system #[green]%s#[reset] %s", 
        ecs_get_name(world, system), 
        activate ? "activated" : "deactivated");
}

/* Actually enable or disable system */
static
void ecs_enable_system(
    ecs_world_t *world,
    ecs_entity_t system,
    EcsSystem *system_data,
    bool enabled)
{
    ecs_assert(!world->is_readonly, ECS_INTERNAL_ERROR, NULL);

    ecs_query_t *query = system_data->query;
    if (!query) {
        return;
    }

    if (ecs_vector_count(query->tables)) {
        /* Only (de)activate system if it has non-empty tables. */
        ecs_system_activate(world, system, enabled, system_data);
        system_data = ecs_get_mut(world, system, EcsSystem, NULL);
    }

    /* Enable/disable systems that trigger on [in] enablement */
    activate_in_columns(
        world, 
        query, 
        world->on_enable_components, 
        enabled);
    
    /* Invoke action for enable/disable status */
    invoke_status_action(
        world, system, system_data,
        enabled ? EcsSystemEnabled : EcsSystemDisabled);
}

static
void ecs_system_init(
    ecs_world_t *world,
    ecs_entity_t system,
    ecs_iter_action_t action,
    ecs_query_t *query,
    void *ctx)
{
    ecs_assert(!world->is_readonly, ECS_INVALID_WHILE_ITERATING, NULL);

    /* Add & initialize the EcsSystem component */
    bool is_added = false;
    EcsSystem *sptr = ecs_get_mut(world, system, EcsSystem, &is_added);
    ecs_assert(sptr != NULL, ECS_INTERNAL_ERROR, NULL);

    if (!is_added) {
        ecs_assert(sptr->query == query, ECS_INVALID_PARAMETER, NULL);
    } else {
        memset(sptr, 0, sizeof(EcsSystem));
        sptr->query = query;
        sptr->entity = system;
        sptr->tick_source = 0;
        sptr->time_spent = 0;
    }

    /* Sanity check to make sure creating the query didn't add any additional
     * tags or components to the system */
    sptr->action = action;
    sptr->ctx = ctx;

    /* Only run this code when the system is created for the first time */
    if (is_added) {
        /* If tables have been matched with this system it is active, and we
         * should activate the in terms, if any. This will ensure that any
         * OnDemand systems get enabled. */
        if (ecs_vector_count(query->tables)) {
            ecs_system_activate(world, system, true, sptr);
        } else {
            /* If system isn't matched with any tables, mark it as inactive. This
             * causes it to be ignored by the main loop. When the system matches
             * with a table it will be activated. */
            ecs_add_id(world, system, EcsInactive);
        }

        /* If system is enabled, trigger enable components */
        activate_in_columns(world, query, world->on_enable_components, true);

        /* If the query has a OnDemand system tag, register its [out] terms */
        if (ecs_has_id(world, system, EcsOnDemand)) {
            register_out_columns(world, system, sptr);
            ecs_assert(sptr->on_demand != NULL, ECS_INTERNAL_ERROR, NULL);

            /* If there are no systems currently interested in any of the [out]
             * terms of the on demand system, disable it */
            if (!sptr->on_demand->count) {
                ecs_add_id(world, system, EcsDisabledIntern);
            }        
        }

        /* Check if system has out columns */
        ecs_term_t *terms = query->filter.terms;
        int32_t i, count = query->filter.term_count;
        for (i = 0; i < count; i ++) {
            if (terms[i].inout != EcsIn) {
                break;
            }
        }
    }

    ecs_trace_1("system #[green]%s#[reset] created with #[red]%s", 
        ecs_get_name(world, system), query->filter.expr);
}

/* -- Public API -- */

void ecs_enable(
    ecs_world_t *world,
    ecs_entity_t entity,
    bool enabled)
{
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_PARAMETER, NULL);

    const EcsType *type_ptr = ecs_get( world, entity, EcsType);
    if (type_ptr) {
        /* If entity is a type, disable all entities in the type */
        ecs_vector_each(type_ptr->normalized, ecs_entity_t, e, {
            ecs_enable(world, *e, enabled);
        });
    } else {
        if (enabled) {
            ecs_remove_id(world, entity, EcsDisabled);
        } else {
            ecs_add_id(world, entity, EcsDisabled);
        }
    }
}

void ecs_set_system_status_action(
    ecs_world_t *world,
    ecs_entity_t system,
    ecs_system_status_action_t action,
    const void *ctx)
{
    EcsSystem *system_data = ecs_get_mut(world, system, EcsSystem, NULL);
    ecs_assert(system_data != NULL, ECS_INVALID_PARAMETER, NULL);

    system_data->status_action = action;
    system_data->status_ctx = (void*)ctx;

    if (!ecs_has_id(world, system, EcsDisabled)) {
        /* If system is already enabled, generate enable status. The API 
         * should guarantee that it exactly matches enable-disable 
         * notifications and activate-deactivate notifications. */
        invoke_status_action(world, system, system_data, EcsSystemEnabled);

        /* If column system has active (non-empty) tables, also generate the
         * activate status. */
        if (ecs_vector_count(system_data->query->tables)) {
            invoke_status_action(
                world, system, system_data, EcsSystemActivated);
        }
    }
}

ecs_entity_t ecs_run_intern(
    ecs_world_t *world,
    ecs_stage_t *stage,
    ecs_entity_t system,
    EcsSystem *system_data,
    int32_t stage_current,
    int32_t stage_count,    
    FLECS_FLOAT delta_time,
    int32_t offset,
    int32_t limit,
    const ecs_filter_t *filter,
    void *param) 
{
    if (!param) {
        param = system_data->ctx;
    }

    FLECS_FLOAT time_elapsed = delta_time;
    ecs_entity_t tick_source = system_data->tick_source;

    if (tick_source) {
        const EcsTickSource *tick = ecs_get(
            world, tick_source, EcsTickSource);

        if (tick) {
            time_elapsed = tick->time_elapsed;

            /* If timer hasn't fired we shouldn't run the system */
            if (!tick->tick) {
                return 0;
            }
        } else {
            /* If a timer has been set but the timer entity does not have the
             * EcsTimer component, don't run the system. This can be the result
             * of a single-shot timer that has fired already. Not resetting the
             * timer field of the system will ensure that the system won't be
             * ran after the timer has fired. */
            return 0;
        }
    }

    ecs_time_t time_start;
    bool measure_time = world->measure_system_time;
    if (measure_time) {
        ecs_os_get_time(&time_start);
    }
    
    ecs_defer_begin(stage->thread_ctx);

    /* Prepare the query iterator */
    ecs_iter_t it = ecs_query_iter_page(system_data->query, offset, limit);
    it.world = stage->thread_ctx;
    it.system = system;
    it.delta_time = delta_time;
    it.delta_system_time = time_elapsed;
    it.world_time = world->stats.world_time_total;
    it.frame_offset = offset;
    
    /* Set param if provided, otherwise use system context */
    if (param) {
        it.param = param;
    } else {
        it.param = system_data->ctx;
    }

    ecs_iter_action_t action = system_data->action;

    /* If no filter is provided, just iterate tables & invoke action */
    if (stage_count <= 1) {
        while (ecs_query_next_w_filter(&it, filter)) {
            action(&it);
        }
    } else {
        while (ecs_query_next_worker(&it, stage_current, stage_count)) {
            action(&it);               
        }
    }

    ecs_defer_end(stage->thread_ctx);

    if (measure_time) {
        system_data->time_spent += (FLECS_FLOAT)ecs_time_measure(&time_start);
    }

    system_data->invoke_count ++;

    return it.interrupted_by;
}

/* -- Public API -- */

ecs_entity_t ecs_run_w_filter(
    ecs_world_t *world,
    ecs_entity_t system,
    FLECS_FLOAT delta_time,
    int32_t offset,
    int32_t limit,
    const ecs_filter_t *filter,
    void *param)
{
    ecs_stage_t *stage = ecs_stage_from_world(&world);

    EcsSystem *system_data = (EcsSystem*)ecs_get(
        world, system, EcsSystem);
    assert(system_data != NULL);

    return ecs_run_intern(
        world, stage, system, system_data, 0, 0, delta_time, offset, limit, 
        filter, param);
}

ecs_entity_t ecs_run_worker(
    ecs_world_t *world,
    ecs_entity_t system,
    int32_t stage_current,
    int32_t stage_count,
    FLECS_FLOAT delta_time,
    void *param)
{
    ecs_stage_t *stage = ecs_stage_from_world(&world);

    EcsSystem *system_data = (EcsSystem*)ecs_get(
        world, system, EcsSystem);
    assert(system_data != NULL);

    return ecs_run_intern(
        world, stage, system, system_data, stage_current, stage_count, 
        delta_time, 0, 0, NULL, param);
}

ecs_entity_t ecs_run(
    ecs_world_t *world,
    ecs_entity_t system,
    FLECS_FLOAT delta_time,
    void *param)
{
    return ecs_run_w_filter(world, system, delta_time, 0, 0, NULL, param);
}

void ecs_run_monitor(
    ecs_world_t *world,
    ecs_matched_query_t *monitor,
    ecs_entities_t *components,
    int32_t row,
    int32_t count,
    ecs_entity_t *entities)
{
    ecs_query_t *query = monitor->query;
    ecs_assert(query != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_entity_t system = query->system;
    const EcsSystem *system_data = ecs_get(world, system, EcsSystem);
    ecs_assert(system_data != NULL, ECS_INTERNAL_ERROR, NULL);

    if (!system_data->action) {
        return;
    }

    ecs_iter_t it = {0};
    ecs_query_set_iter( world, query, &it, 
        monitor->matched_table_index, row, count);

    it.world = world;
    it.triggered_by = components;
    it.param = system_data->ctx;

    if (entities) {
        it.entities = entities;
    }

    // printf("Run monitor %s\n", ecs_get_name(world, system));

    it.system = system;
    system_data->action(&it);
}

ecs_query_t* ecs_get_query(
    const ecs_world_t *world,
    ecs_entity_t system)
{
    const EcsQuery *q = ecs_get(world, system, EcsQuery);
    if (q) {
        return q->query;
    } else {
        return NULL;
    }
}

/* Generic constructor to initialize a component to 0 */
static
void sys_ctor_init_zero(
    ecs_world_t *world,
    ecs_entity_t component,
    const ecs_entity_t *entities,
    void *ptr,
    size_t size,
    int32_t count,
    void *ctx)
{
    (void)world;
    (void)component;
    (void)entities;
    (void)ctx;
    memset(ptr, 0, size * (size_t)count);
}

/* System destructor */
static
void ecs_colsystem_dtor(
    ecs_world_t *world,
    ecs_entity_t component,
    const ecs_entity_t *entities,
    void *ptr,
    size_t size,
    int32_t count,
    void *ctx)
{
    (void)component;
    (void)ctx;
    (void)size;

    EcsSystem *system_data = ptr;

    int i;
    for (i = 0; i < count; i ++) {
        EcsSystem *cur = &system_data[i];
        ecs_entity_t e = entities[i];

        /* Invoke Deactivated action for active systems */
        if (cur->query && ecs_vector_count(cur->query->tables)) {
            invoke_status_action(world, e, ptr, EcsSystemDeactivated);
        }

        /* Invoke Disabled action for enabled systems */
        if (!ecs_has_id(world, e, EcsDisabled) && 
            !ecs_has_id(world, e, EcsDisabledIntern)) 
        {
            invoke_status_action(world, e, ptr, EcsSystemDisabled);
        }           

        ecs_os_free(cur->on_demand);
    }
}

static
void OnSetTriggerCtx(
    ecs_iter_t *it)
{
    EcsTrigger *ct = ecs_term(it, EcsTrigger, 1);
    EcsContext *ctx = ecs_term(it, EcsContext, 2);

    int32_t i;
    for (i = 0; i < it->count; i ++) {
        ((ecs_trigger_t*)ct[i].trigger)->ctx = (void*)ctx[i].ctx;
    }  
}

/* System that registers component lifecycle callbacks */
static
void OnSetComponentLifecycle(
    ecs_iter_t *it)
{
    EcsComponentLifecycle *cl = ecs_term(it, EcsComponentLifecycle, 1);
    ecs_world_t *world = it->world;

    int i;
    for (i = 0; i < it->count; i ++) {
        ecs_entity_t e = it->entities[i];
        ecs_set_component_actions_w_id(world, e, &cl[i]);   
    }
}

/* Disable system when EcsDisabled is added */
static 
void DisableSystem(
    ecs_iter_t *it)
{
    EcsSystem *system_data = ecs_term(it, EcsSystem, 1);

    int32_t i;
    for (i = 0; i < it->count; i ++) {
        ecs_enable_system(
            it->world, it->entities[i], &system_data[i], false);
    }
}

/* Enable system when EcsDisabled is removed */
static
void EnableSystem(
    ecs_iter_t *it)
{
    EcsSystem *system_data = ecs_term(it, EcsSystem, 1);

    int32_t i;
    for (i = 0; i < it->count; i ++) {
        ecs_enable_system(
            it->world, it->entities[i], &system_data[i], true);
    }
}

/* Create a system from a query and an action */
static
void CreateSystem(
    ecs_iter_t *it)
{
    ecs_world_t *world = it->world;
    ecs_entity_t *entities = it->entities;

    EcsQuery *query = ecs_term(it, EcsQuery, 1);
    EcsIterAction *action = ecs_term(it, EcsIterAction, 2);
    EcsContext *ctx = ecs_term(it, EcsContext, 3);
    
    int32_t i;
    for (i = 0; i < it->count; i ++) {
        ecs_entity_t e = entities[i];
        void *ctx_ptr = NULL;
        if (ctx) {
            ctx_ptr = (void*)ctx[i].ctx;
        }

        ecs_system_init(world, e, action[i].action, query[i].query, ctx_ptr);
    }
}

static
void bootstrap_set_system(
    ecs_world_t *world,
    const char *name,
    const char *expr,
    ecs_iter_action_t action)
{
    ecs_entity_t system = ecs_set(world, 0, EcsName, {.value = name});
    ecs_add_id(world, system, EcsOnSet);

    ecs_query_t *query = ecs_query_init(world, &(ecs_query_desc_t){
        .filter.name = name,
        .filter.expr = expr,
        .system = system
    });

    ecs_system_init(world, system, action, query, NULL);
}

ecs_entity_t ecs_new_system(
    ecs_world_t *world,
    ecs_entity_t e,
    const char *name,
    ecs_entity_t tag,
    const char *expr,
    ecs_iter_action_t action)
{
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_FROM_WORKER, NULL);
    ecs_assert(!world->is_readonly, ECS_INVALID_WHILE_ITERATING, NULL);

    ecs_entity_t result = ecs_entity_init(world, &(ecs_entity_desc_t){
        .entity = e,
        .name = name,
        .add = {tag}
    });

    ecs_assert(result != 0, ECS_INTERNAL_ERROR, NULL);
    
    ecs_set(world, result, EcsIterAction, {action});

    const EcsQuery *q = ecs_get(world, result, EcsQuery);
    if (q) {
        const char *query_expr = q->query->filter.expr;
        if (!query_expr || !expr) {
            if (query_expr != expr) {
                if (query_expr && !strcmp(query_expr, "0")) {
                    /* Ok */
                } else if (expr && !strcmp(expr, "0")) {
                    /* Ok */
                } else {
                    ecs_abort(ECS_ALREADY_DEFINED, NULL);
                }
            }
        } else {
            if (strcmp(query_expr, expr)) {
                ecs_abort(ECS_ALREADY_DEFINED, name);
            }
        }
    } else {
        ecs_query_t *query = ecs_query_init(world, &(ecs_query_desc_t){
            .filter.name = name,
            .filter.expr = expr,
            .system = result
        });

        if (!query) {
            ecs_delete(world, result);
            return 0;
        }

        ecs_set(world, result, EcsQuery, {query});
    }

    return result;
}

void FlecsSystemImport(
    ecs_world_t *world)
{
    ECS_MODULE(world, FlecsSystem);

    ecs_set_name_prefix(world, "Ecs");

    ecs_bootstrap_component(world, EcsComponentLifecycle);
    ecs_bootstrap_component(world, EcsSystem);
    ecs_bootstrap_component(world, EcsTickSource);
    ecs_bootstrap_component(world, EcsIterAction);
    ecs_bootstrap_component(world, EcsContext);

    ecs_bootstrap_tag(world, EcsOnAdd);
    ecs_bootstrap_tag(world, EcsOnRemove);
    ecs_bootstrap_tag(world, EcsOnSet);
    ecs_bootstrap_tag(world, EcsUnSet);

    /* Put following tags in flecs.core so they can be looked up
     * without using the flecs.systems prefix. */
    ecs_entity_t old_scope = ecs_set_scope(world, EcsFlecsCore);
    ecs_bootstrap_tag(world, EcsDisabledIntern);
    ecs_bootstrap_tag(world, EcsInactive);
    ecs_bootstrap_tag(world, EcsOnDemand);
    ecs_bootstrap_tag(world, EcsMonitor);
    ecs_set_scope(world, old_scope);

    ECS_TYPE_IMPL(EcsComponentLifecycle);
    ECS_TYPE_IMPL(EcsSystem);
    ECS_TYPE_IMPL(EcsTickSource);
    ECS_TYPE_IMPL(EcsIterAction);
    ECS_TYPE_IMPL(EcsContext);

    /* Bootstrap ctor and dtor for EcsSystem */
    ecs_set_component_actions_w_id(world, ecs_id(EcsSystem), 
        &(EcsComponentLifecycle) {
            .ctor = sys_ctor_init_zero,
            .dtor = ecs_colsystem_dtor
        });

    /* Create systems that creates systems */
    bootstrap_set_system(world,
        "CreateSystem", "Query, IterAction, ?Context, SYSTEM:Hidden", 
        CreateSystem);

    /* From here we can create systems */

    /* Register OnSet system for EcsComponentLifecycle */
    ECS_SYSTEM(world, OnSetComponentLifecycle, EcsOnSet, 
        ComponentLifecycle, SYSTEM:Hidden);

    /* System that sets ctx for a trigger */
    ECS_SYSTEM(world, OnSetTriggerCtx, EcsOnSet, 
        Trigger, Context, SYSTEM:Hidden);

    /* Monitors that trigger when a system is enabled or disabled */
    ECS_SYSTEM(world, DisableSystem, EcsMonitor, 
        System, Disabled || DisabledIntern, SYSTEM:Hidden);

    ECS_SYSTEM(world, EnableSystem, EcsMonitor, 
        System, !Disabled, !DisabledIntern, SYSTEM:Hidden);
}

#endif


#ifdef FLECS_SYSTEM
#ifdef FLECS_DBG


int ecs_dbg_system(
    const ecs_world_t *world,
    ecs_entity_t system,
    ecs_dbg_system_t *dbg_out)
{
    const EcsSystem *system_data = ecs_get(world, system, EcsSystem);
    if (!system_data) {
        return -1;
    }

    *dbg_out = (ecs_dbg_system_t){.system = system};
    dbg_out->active_table_count = ecs_vector_count(system_data->query->tables);
    dbg_out->inactive_table_count = ecs_vector_count(system_data->query->empty_tables);
    dbg_out->enabled = !ecs_has_id(world, system, EcsDisabled);

    ecs_vector_each(system_data->query->tables, ecs_matched_table_t, mt, {
        ecs_table_t *table = mt->iter_data.table;
        if (table) {
            dbg_out->entities_matched_count += ecs_table_count(table);
        }        
    });

    /* Inactive tables are inactive because they are empty, so no need to 
     * iterate them */

    return 0;
}

bool ecs_dbg_match_entity(
    const ecs_world_t *world,
    ecs_entity_t entity,
    ecs_entity_t system,
    ecs_match_failure_t *failure_info_out)
{
    ecs_dbg_entity_t dbg;
    ecs_dbg_entity(world, entity, &dbg);

    const EcsSystem *system_data = ecs_get(world, system, EcsSystem);
    if (!system_data) {
        failure_info_out->reason = EcsMatchNotASystem;
        failure_info_out->column = -1;
        return false;
    }

    return ecs_query_match(
        world, dbg.table, system_data->query, failure_info_out);
}

ecs_type_t ecs_dbg_get_column_type(
    ecs_world_t *world,
    ecs_entity_t system,
    int32_t column_index)
{
    const EcsSystem *system_data = ecs_get(world, system, EcsSystem);
    if (!system_data) {
        return NULL;
    }
    
    ecs_term_t *terms = system_data->query->filter.terms;
    int32_t count = system_data->query->filter.term_count;

    if (count < column_index) {
        return NULL;
    }

    ecs_term_t *term = &terms[column_index - 1];
    
    return ecs_type_from_id(world, term->id);
}

#endif
#endif

static
ecs_vector_t* sort_and_dedup(
    ecs_vector_t *result)
{
    /* Sort vector */
    ecs_vector_sort(result, ecs_id_t, ecs_entity_compare_qsort);

    /* Ensure vector doesn't contain duplicates */
    ecs_id_t *ids = ecs_vector_first(result, ecs_id_t);
    int32_t i, offset = 0, count = ecs_vector_count(result);

    for (i = 0; i < count; i ++) {
        if (i && ids[i] == ids[i - 1]) {
            offset ++;
        }

        if (i + offset >= count) {
            break;
        }

        ids[i] = ids[i + offset];
    }

    ecs_vector_set_count(&result, ecs_id_t, i - offset);

    return result;
}

/** Parse callback that adds type to type identifier */
static
ecs_vector_t* expr_to_ids(
    ecs_world_t *world,
    const char *name,
    const char *expr)
{
#ifdef FLECS_PARSER    
    ecs_vector_t *result = NULL;
    const char *ptr = expr;
    ecs_term_t term = {0};

    if (!ptr) {
        return NULL;
    }

    while (ptr[0] && (ptr = ecs_parse_term(world, name, expr, ptr, &term))) {
        if (term.name) {
            ecs_parser_error(name, expr, (ptr - expr), 
                "column names not supported in type expression");
            goto error;
        }

        if (term.oper != EcsAnd && term.oper != EcsAndFrom) {
            ecs_parser_error(name, expr, (ptr - expr), 
                "operator other than AND not supported in type expression");
            goto error;
        }

        if (ecs_term_finalize(world, name, expr, &term)) {
            goto error;
        }

        if (term.args[0].entity == 0) {
            /* Empty term */
            goto done;
        }

        if (term.args[0].set != EcsDefaultSet) {
            ecs_parser_error(name, expr, (ptr - expr), 
                "source modifiers not supported for type expressions");
            goto error;
        }

        if (term.args[0].entity != EcsThis) {
            ecs_parser_error(name, expr, (ptr - expr), 
                "subject other than this not supported in type expression");
            goto error;
        }

        if (term.oper == EcsAndFrom) {
            term.role = ECS_AND;
        }

        ecs_id_t* elem = ecs_vector_add(&result, ecs_id_t);
        *elem = term.id | term.role;

        ecs_term_fini(&term);
    }

    result = sort_and_dedup(result);

done:
    return result;
error:
    ecs_term_fini(&term);
    ecs_vector_free(result);
    return NULL;
#else
    (void)world;
    (void)name;
    (void)expr;
    ecs_abort(ECS_UNSUPPORTED, "parser addon is not available");
    return NULL;
#endif    
}

/* Create normalized type. A normalized type resolves all elements with an
 * AND flag and appends them to the resulting type, where the default type
 * maintains the original type hierarchy. */
static
ecs_vector_t* ids_to_normalized_ids(
    ecs_world_t *world,
    ecs_vector_t *ids)
{
    ecs_vector_t *result = NULL;

    ecs_entity_t *array = ecs_vector_first(ids, ecs_id_t);
    int32_t i, count = ecs_vector_count(ids);

    for (i = 0; i < count; i ++) {
        ecs_entity_t e = array[i];
        if (ECS_HAS_ROLE(e, AND)) {
            ecs_entity_t entity = ECS_PAIR_OBJECT(e);

            const EcsType *type_ptr = ecs_get(world, entity, EcsType);
            ecs_assert(type_ptr != NULL, ECS_INVALID_PARAMETER, 
                "flag must be applied to type");

            ecs_vector_each(type_ptr->normalized, ecs_id_t, c_ptr, {
                ecs_entity_t *el = ecs_vector_add(&result, ecs_id_t);
                *el = *c_ptr;
            })
        } else {
            ecs_entity_t *el = ecs_vector_add(&result, ecs_id_t);
            *el = e;
        }   
    }

    return sort_and_dedup(result);
}

static
ecs_table_t* table_from_ids(
    ecs_world_t *world,
    ecs_vector_t *ids)
{
    ecs_entities_t ids_array = ecs_type_to_entities(ids);
    ecs_table_t *result = ecs_table_find_or_create(world, &ids_array);
    return result;
}

/* If a name prefix is set with ecs_set_name_prefix, check if the entity name
 * has the prefix, and if so remove it. This enables using prefixed names in C
 * for components / systems while storing a canonical / language independent 
 * identifier. */
const char* ecs_name_from_symbol(
    ecs_world_t *world,
    const char *type_name)
{
    const char *prefix = world->name_prefix;
    if (type_name && prefix) {
        ecs_size_t len = ecs_os_strlen(prefix);
        if (!ecs_os_strncmp(type_name, prefix, len) && 
           (isupper(type_name[len]) || type_name[len] == '_')) 
        {
            if (type_name[len] == '_') {
                return type_name + len + 1;
            } else {
                return type_name + len;
            }
        }
    }

    return type_name;
}

void ecs_set_symbol(
    ecs_world_t *world,
    ecs_entity_t e,
    const char *name)
{
    if (!name) {
        return;
    }
    
    const char *e_name = ecs_name_from_symbol(world, name);

    EcsName *name_ptr = ecs_get_mut(world, e, EcsName, NULL);
    name_ptr->value = e_name;

    if (name_ptr->symbol) {
        ecs_os_free(name_ptr->symbol);
    }

    name_ptr->symbol = ecs_os_strdup(name);
}

ecs_entity_t ecs_lookup_w_id(
    ecs_world_t *world,
    ecs_entity_t e,
    const char *name)
{
    if (e) {
        /* If explicit id was provided but it does not exist in the world, make
         * sure it has the proper scope. This can happen when an entity was 
         * defined in another world. */
        if (!ecs_exists(world, e)) {
            ecs_entity_t scope = world->stage.scope;
            if (scope) {
                ecs_add_pair(world, e, EcsChildOf, scope);
            }
        }

        if (name) {
            /* Make sure name is the same */
            const char *existing = ecs_get_name(world, e);
            if (existing && strcmp(existing, name)) {
                ecs_abort(ECS_INCONSISTENT_NAME, name);
            }
            if (!existing) {
                ecs_set_symbol(world, e, name);
            }
        }
    }
    
    ecs_entity_t result = e;
    if (!result) {
        if (!name) {
            /* If neither an id nor name is specified, return 0 */
            return 0;
        }

        result = ecs_lookup(world, name);
    }
    
    return result;
}

/* -- Public functions -- */

ecs_type_t ecs_type_from_str(
    ecs_world_t *world,
    const char *expr)
{
    ecs_vector_t *ids = expr_to_ids(world, NULL, expr);
    if (!ids) {
        return NULL;
    }

    ecs_vector_t *normalized_ids = ids_to_normalized_ids(world, ids);
    ecs_vector_free(ids);

    ecs_table_t *table = table_from_ids(world, normalized_ids);
    ecs_vector_free(normalized_ids);

    return table->type;
}

ecs_table_t* ecs_table_from_str(
    ecs_world_t *world,
    const char *expr)
{
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_OPERATION, NULL);

    ecs_vector_t *ids = expr_to_ids(world, NULL, expr);
    if (!ids) {
        return NULL;
    }

    ecs_table_t *result = table_from_ids(world, ids);
    ecs_vector_free(ids);

    return result;
}

/* Global type variables */
ecs_type_t ecs_type(EcsComponent);
ecs_type_t ecs_type(EcsType);
ecs_type_t ecs_type(EcsName);
ecs_type_t ecs_type(EcsQuery);
ecs_type_t ecs_type(EcsTrigger);
ecs_type_t ecs_type(EcsPrefab);

/* Component lifecycle actions for EcsName */
static ECS_CTOR(EcsName, ptr, {
    ptr->value = NULL;
    ptr->alloc_value = NULL;
    ptr->symbol = NULL;
})

static ECS_DTOR(EcsName, ptr, {
    ecs_os_free(ptr->alloc_value);
    ecs_os_free(ptr->symbol);
    ptr->value = NULL;
    ptr->alloc_value = NULL;
    ptr->symbol = NULL;
})

static ECS_COPY(EcsName, dst, src, {
    if (dst->alloc_value) {
        ecs_os_free(dst->alloc_value);
        dst->alloc_value = NULL;
    }

    if (dst->symbol) {
        ecs_os_free(dst->symbol);
        dst->symbol = NULL;
    }
    
    if (src->alloc_value) {
        dst->alloc_value = ecs_os_strdup(src->alloc_value);
        dst->value = dst->alloc_value;
    } else {
        dst->alloc_value = NULL;
        dst->value = src->value;
    }

    if (src->symbol) {
        dst->symbol = ecs_os_strdup(src->symbol);
    }
})

static ECS_MOVE(EcsName, dst, src, {
    if (dst->alloc_value) {
        ecs_os_free(dst->alloc_value);
    }
    if (dst->symbol) {
        ecs_os_free(dst->symbol);
    }

    dst->value = src->value;
    dst->alloc_value = src->alloc_value;
    dst->symbol = src->symbol;

    src->value = NULL;
    src->alloc_value = NULL;
    src->symbol = NULL;
})

static
void register_on_delete(ecs_iter_t *it) {
    ecs_id_t id = ecs_term_id(it, 1);
    int i;
    for (i = 0; i < it->count; i ++) {
        ecs_entity_t e = it->entities[i];
        ecs_id_record_t *r = ecs_ensure_id_record(it->world, e);
        ecs_assert(r != NULL, ECS_INTERNAL_ERROR, NULL);
        r->on_delete = ECS_PAIR_OBJECT(id);

        r = ecs_ensure_id_record(it->world, ecs_pair(e, EcsWildcard));
        ecs_assert(r != NULL, ECS_INTERNAL_ERROR, NULL);
        r->on_delete = ECS_PAIR_OBJECT(id);

        ecs_set_watch(it->world, e);
    }
}

static
void register_on_delete_object(ecs_iter_t *it) {
    ecs_id_t id = ecs_term_id(it, 1);
    int i;
    for (i = 0; i < it->count; i ++) {
        ecs_entity_t e = it->entities[i];
        ecs_id_record_t *r = ecs_ensure_id_record(it->world, e);
        ecs_assert(r != NULL, ECS_INTERNAL_ERROR, NULL);
        r->on_delete_object = ECS_PAIR_OBJECT(id);

        ecs_set_watch(it->world, e);
    }    
}

/* -- Bootstrapping -- */

#define bootstrap_component(world, table, name)\
    _bootstrap_component(world, table, ecs_id(name), #name, sizeof(name),\
        ECS_ALIGNOF(name))

static
void _bootstrap_component(
    ecs_world_t *world,
    ecs_table_t *table,
    ecs_entity_t entity,
    const char *id,
    ecs_size_t size,
    ecs_size_t alignment)
{
    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_data_t *data = ecs_table_get_or_create_data(table);
    ecs_assert(data != NULL, ECS_INTERNAL_ERROR, NULL);

    ecs_column_t *columns = data->columns;
    ecs_assert(columns != NULL, ECS_INTERNAL_ERROR, NULL);

    /* Create record in entity index */
    ecs_record_t *record = ecs_eis_ensure(world, entity);
    record->table = table;

    /* Insert row into table to store EcsComponent itself */
    int32_t index = ecs_table_append(world, table, data, entity, record, false);
    record->row = index + 1;

    /* Set size and id */
    EcsComponent *c_info = ecs_vector_first(columns[0].data, EcsComponent);
    EcsName *id_data = ecs_vector_first(columns[1].data, EcsName);
    
    c_info[index].size = size;
    c_info[index].alignment = alignment;
    id_data[index].value = &id[ecs_os_strlen("Ecs")]; /* Skip prefix */
    id_data[index].symbol = ecs_os_strdup(id);
    id_data[index].alloc_value = NULL;
}

/** Create type for component */
ecs_type_t ecs_bootstrap_type(
    ecs_world_t *world,
    ecs_entity_t entity)
{
    ecs_table_t *table = ecs_table_find_or_create(world, &(ecs_entities_t){
        .array = (ecs_entity_t[]){entity},
        .count = 1
    });

    ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(table->type != NULL, ECS_INTERNAL_ERROR, NULL);

    return table->type;
}

/** Bootstrap types for builtin components and tags */
static
void bootstrap_types(
    ecs_world_t *world)
{
    ecs_type(EcsComponent) = ecs_bootstrap_type(world, ecs_id(EcsComponent));
    ecs_type(EcsType) = ecs_bootstrap_type(world, ecs_id(EcsType));
    ecs_type(EcsName) = ecs_bootstrap_type(world, ecs_id(EcsName));
}

/** Initialize component table. This table is manually constructed to bootstrap
 * flecs. After this function has been called, the builtin components can be
 * created. 
 * The reason this table is constructed manually is because it requires the size
 * and alignment of the EcsComponent and EcsName components, which haven't been 
 * created yet */
static
ecs_table_t* bootstrap_component_table(
    ecs_world_t *world)
{
    ecs_entity_t entities[] = {ecs_id(EcsComponent), ecs_id(EcsName), ecs_pair(EcsChildOf, EcsFlecsCore)};
    ecs_entities_t array = {
        .array = entities,
        .count = 3
    };

    ecs_table_t *result = ecs_table_find_or_create(world, &array);
    ecs_data_t *data = ecs_table_get_or_create_data(result);

    /* Preallocate enough memory for initial components */
    data->entities = ecs_vector_new(ecs_entity_t, EcsFirstUserComponentId);
    data->record_ptrs = ecs_vector_new(ecs_record_t*, EcsFirstUserComponentId);

    data->columns = ecs_os_malloc(sizeof(ecs_column_t) * 2);
    ecs_assert(data->columns != NULL, ECS_OUT_OF_MEMORY, NULL);

    data->columns[0].data = ecs_vector_new(EcsComponent, EcsFirstUserComponentId);
    data->columns[0].size = sizeof(EcsComponent);
    data->columns[0].alignment = ECS_ALIGNOF(EcsComponent);
    data->columns[1].data = ecs_vector_new(EcsName, EcsFirstUserComponentId);
    data->columns[1].size = sizeof(EcsName);
    data->columns[1].alignment = ECS_ALIGNOF(EcsName);

    result->column_count = 2;
    
    return result;
}

static
void bootstrap_entity(
    ecs_world_t *world,
    ecs_entity_t id,
    const char *name,
    ecs_entity_t parent)
{
    ecs_set(world, id, EcsName, {.value = name});
    ecs_assert(ecs_get_name(world, id) != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_add_pair(world, id, EcsChildOf, parent);

    if (!parent || parent == EcsFlecsCore) {
        ecs_assert(ecs_lookup_fullpath(world, name) == id, 
            ECS_INTERNAL_ERROR, NULL);
    }
}

void ecs_bootstrap(
    ecs_world_t *world)
{
    ecs_type(EcsComponent) = NULL;

    ecs_trace_1("bootstrap core components");
    ecs_log_push();

    /* Create table that will hold components (EcsComponent, EcsName) */
    ecs_table_t *table = bootstrap_component_table(world);
    assert(table != NULL);

    bootstrap_component(world, table, EcsName);
    bootstrap_component(world, table, EcsComponent);
    bootstrap_component(world, table, EcsType);
    bootstrap_component(world, table, EcsQuery);
    bootstrap_component(world, table, EcsTrigger);

    ecs_set_component_actions(world, EcsName, {
        .ctor = ecs_ctor(EcsName),
        .dtor = ecs_dtor(EcsName),
        .copy = ecs_copy(EcsName),
        .move = ecs_move(EcsName)
    });    

    world->stats.last_component_id = EcsFirstUserComponentId;
    world->stats.last_id = EcsFirstUserEntityId;
    world->stats.min_id = 0;
    world->stats.max_id = 0;

    bootstrap_types(world);

    ecs_set_scope(world, EcsFlecsCore);

    ecs_bootstrap_tag(world, EcsModule);
    ecs_bootstrap_tag(world, EcsPrefab);
    ecs_bootstrap_tag(world, EcsHidden);
    ecs_bootstrap_tag(world, EcsDisabled);

    /* Initialize scopes */
    ecs_set(world, EcsFlecs, EcsName, {.value = "flecs"});
    ecs_add_id(world, EcsFlecs, EcsModule);
    ecs_set(world, EcsFlecsCore, EcsName, {.value = "core"});
    ecs_add_id(world, EcsFlecsCore, EcsModule);
    ecs_add_pair(world, EcsFlecsCore, EcsChildOf, EcsFlecs);

    /* Initialize builtin entities */
    bootstrap_entity(world, EcsWorld, "World", EcsFlecsCore);
    bootstrap_entity(world, EcsSingleton, "$", EcsFlecsCore);
    bootstrap_entity(world, EcsThis, "This", EcsFlecsCore);
    bootstrap_entity(world, EcsWildcard, "*", EcsFlecsCore);
    bootstrap_entity(world, EcsTransitive, "Transitive", EcsFlecsCore);
    bootstrap_entity(world, EcsFinal, "Final", EcsFlecsCore);
    bootstrap_entity(world, EcsIsA, "IsA", EcsFlecsCore);
    bootstrap_entity(world, EcsChildOf, "ChildOf", EcsFlecsCore);
    bootstrap_entity(world, EcsOnDelete, "OnDelete", EcsFlecsCore);
    bootstrap_entity(world, EcsOnDeleteObject, "OnDeleteObject", EcsFlecsCore);
    bootstrap_entity(world, EcsRemove, "Remove", EcsFlecsCore);
    bootstrap_entity(world, EcsDelete, "Delete", EcsFlecsCore);
    bootstrap_entity(world, EcsThrow, "Throw", EcsFlecsCore);

    /* Mark entities as transitive */
    ecs_add_id(world, EcsIsA, EcsTransitive);

    /* Mark entities as final */
    ecs_add_id(world, ecs_id(EcsComponent), EcsFinal);
    ecs_add_id(world, ecs_id(EcsName), EcsFinal);
    ecs_add_id(world, EcsTransitive, EcsFinal);
    ecs_add_id(world, EcsFinal, EcsFinal);
    ecs_add_id(world, EcsIsA, EcsFinal);
    ecs_add_id(world, EcsOnDelete, EcsFinal);
    ecs_add_id(world, EcsOnDeleteObject, EcsFinal);

    /* Define triggers for when relationship cleanup rules are assigned */
    ecs_trigger_init(world, &(ecs_trigger_desc_t){
        .term = {.id = ecs_pair(EcsOnDelete, EcsWildcard)},
        .callback = register_on_delete,
        .events = {EcsOnAdd}
    });

    ecs_trigger_init(world, &(ecs_trigger_desc_t){
        .term = {.id = ecs_pair(EcsOnDeleteObject, EcsWildcard)},
        .callback = register_on_delete_object,
        .events = {EcsOnAdd}
    });  

    /* Removal of ChildOf objects (parents) deletes the subject (child) */
    ecs_add_pair(world, EcsChildOf, EcsOnDeleteObject, EcsDelete);  

    ecs_set_scope(world, 0);

    ecs_log_pop();
}


static
bool path_append(
    const ecs_world_t *world, 
    ecs_entity_t parent, 
    ecs_entity_t child, 
    ecs_entity_t component,
    const char *sep,
    const char *prefix,
    ecs_strbuf_t *buf)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);

    ecs_type_t type = ecs_get_type(world, child);
    ecs_entity_t cur = ecs_find_in_type(world, type, component, EcsChildOf);
    
    if (cur) {
        if (cur != parent && cur != EcsFlecsCore) {
            path_append(world, parent, cur, component, sep, prefix, buf);
            ecs_strbuf_appendstr(buf, sep);
        }
    } else if (prefix) {
        ecs_strbuf_appendstr(buf, prefix);
    }

    char buff[22];
    const char *name = ecs_get_name(world, child);
    if (!name) {
        ecs_os_sprintf(buff, "%u", (uint32_t)child);
        name = buff;
    }

    ecs_strbuf_appendstr(buf, name);

    return cur != 0;
}

static
ecs_entity_t find_as_alias(
    const ecs_world_t *world,
    const char *name)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);

    int32_t i, count = ecs_vector_count(world->aliases);
    ecs_alias_t *aliases = ecs_vector_first(world->aliases, ecs_alias_t);
    for (i = 0; i < count; i ++) {
        if (!strcmp(aliases[i].name, name)) {
            return aliases[i].entity;
        }
    }

    return 0;
}

static
bool is_number(
    const char *name)
{
    if (!isdigit(name[0])) {
        return false;
    }

    ecs_size_t i, s = ecs_os_strlen(name);
    for (i = 1; i < s; i ++) {
        if (!isdigit(name[i])) {
            break;
        }
    }

    return i >= s;
}

static 
ecs_entity_t name_to_id(
    const char *name)
{
    long int result = atol(name);
    ecs_assert(result >= 0, ECS_INTERNAL_ERROR, NULL);
    return (ecs_entity_t)result;
}

static
ecs_entity_t find_child_in_table(
    const ecs_table_t *table,
    const char *name)
{
    /* If table doesn't have EcsName, then don't bother */
    int32_t name_index = ecs_type_index_of(table->type, ecs_id(EcsName));
    if (name_index == -1) {
        return 0;
    }

    ecs_data_t *data = ecs_table_get_data(table);
    if (!data || !data->columns) {
        return 0;
    }

    int32_t i, count = ecs_vector_count(data->entities);
    if (!count) {
        return 0;
    }

    if (is_number(name)) {
        return name_to_id(name);
    }

    ecs_column_t *column = &data->columns[name_index];
    EcsName *names = ecs_vector_first(column->data, EcsName);

    for (i = 0; i < count; i ++) {
        const char *cur_name = names[i].value;
        const char *cur_sym = names[i].symbol;
        if ((cur_name && !strcmp(cur_name, name)) || (cur_sym && !strcmp(cur_sym, name))) {
            return *ecs_vector_get(data->entities, ecs_entity_t, i);
        }
    }

    return 0;
}

static
ecs_entity_t find_child(
    const ecs_world_t *world,
    ecs_entity_t parent,
    const char *name)
{        
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);

    (void)parent;
    
    ecs_sparse_each(world->store.tables, ecs_table_t, table, {
        ecs_entity_t result = find_child_in_table(table, name);
        if (result) {
            return result;
        }
    });    

    return 0;
}

static
bool is_sep(
    const char **ptr,
    const char *sep)
{
    ecs_size_t len = ecs_os_strlen(sep);

    if (!ecs_os_strncmp(*ptr, sep, len)) {
        *ptr += len - 1;
        return true;
    } else {
        return false;
    }
}

static
const char *path_elem(
    const char *path,
    char *buff,
    const char *sep)
{
    const char *ptr;
    char *bptr, ch;

    for (bptr = buff, ptr = path; (ch = *ptr); ptr ++) {
        ecs_assert(bptr - buff < ECS_MAX_NAME_LENGTH, ECS_INVALID_PARAMETER, 
            NULL);
            
        if (is_sep(&ptr, sep)) {
            *bptr = '\0';
            return ptr + 1;
        } else {
            *bptr = ch;
            bptr ++;
        }
    }

    if (bptr != buff) {
        *bptr = '\0';
        return ptr;
    } else {
        return NULL;
    }
}

static
ecs_entity_t get_parent_from_path(
    const ecs_world_t *world,
    ecs_entity_t parent,
    const char **path_ptr,
    const char *prefix,
    bool new_entity)
{
    bool start_from_root = false;
    const char *path = *path_ptr;
   
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);

    if (prefix) {
        ecs_size_t len = ecs_os_strlen(prefix);
        if (!ecs_os_strncmp(path, prefix, len)) {
            path += len;
            parent = 0;
            start_from_root = true;
        }
    }

    if (!start_from_root && !parent && new_entity) {
        parent = ecs_get_scope(world);
    }

    *path_ptr = path;

    return parent;
}

char* ecs_get_path_w_sep(
    const ecs_world_t *world,
    ecs_entity_t parent,
    ecs_entity_t child,
    ecs_entity_t component,
    const char *sep,
    const char *prefix)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    world = ecs_get_world(world);

    if (!sep) {
        sep = ".";
    }
        
    ecs_strbuf_t buf = ECS_STRBUF_INIT;

    if (parent != child) {
        path_append(world, parent, child, component, sep, prefix, &buf);
    } else {
        ecs_strbuf_appendstr(&buf, "");
    }

    return ecs_strbuf_get(&buf);
}

ecs_entity_t ecs_lookup_child(
    const ecs_world_t *world,
    ecs_entity_t parent,
    const char *name)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    world = ecs_get_world(world);
    ecs_entity_t result = 0;

    ecs_id_record_t *r = ecs_get_id_record(world, ecs_pair(EcsChildOf, parent));
    if (r && r->table_index) {        
        ecs_map_iter_t it = ecs_map_iter(r->table_index);
        ecs_table_record_t *tr;
        while ((tr = ecs_map_next(&it, ecs_table_record_t, NULL))) {
            result = find_child_in_table(tr->table, name);
            if (result) {
                return result;
            }            
        }
    }

    return result;
}

ecs_entity_t ecs_lookup(
    const ecs_world_t *world,
    const char *name)
{   
    if (!name) {
        return 0;
    }

    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    world = ecs_get_world(world);    

    if (is_number(name)) {
        return name_to_id(name);
    }

    ecs_entity_t e = find_as_alias(world, name);
    if (e) {
        return e;
    }    
    
    return ecs_lookup_child(world, 0, name);
}

ecs_entity_t ecs_lookup_symbol(
    const ecs_world_t *world,
    const char *name)
{   
    if (!name) {
        return 0;
    }

    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    world = ecs_get_world(world);    

    if (is_number(name)) {
        return name_to_id(name);
    }   
    
    return find_child(world, 0, name);
}

ecs_entity_t ecs_lookup_path_w_sep(
    const ecs_world_t *world,
    ecs_entity_t parent,
    const char *path,
    const char *sep,
    const char *prefix,
    bool recursive)
{
    if (!path) {
        return 0;
    }

    if (!sep) {
        sep = ".";
    }

    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    world = ecs_get_world(world);

    if (path[0] == '.' && !path[1]) {
        return EcsThis;
    }

    ecs_entity_t e = find_as_alias(world, path);
    if (e) {
        return e;
    }      
    
    char buff[ECS_MAX_NAME_LENGTH];
    const char *ptr;
    ecs_entity_t cur;
    bool core_searched = false;

    if (!sep) {
        sep = ".";
    }

    parent = get_parent_from_path(world, parent, &path, prefix, true);

retry:
    cur = parent;
    ptr = path;

    while ((ptr = path_elem(ptr, buff, sep))) {
        cur = ecs_lookup_child(world, cur, buff);
        if (!cur) {
            goto tail;
        }
    }

tail:
    if (!cur && recursive) {
        if (!core_searched) {
            if (parent) {
                parent = ecs_get_object_w_id(world, parent, EcsChildOf, 0);
            } else {
                parent = EcsFlecsCore;
                core_searched = true;
            }
            goto retry;
        }
    }

    return cur;
}

ecs_entity_t ecs_set_scope(
    ecs_world_t *world,
    ecs_entity_t scope)
{
    ecs_stage_t *stage = ecs_stage_from_world(&world);

    ecs_entity_t e = ecs_pair(EcsChildOf, scope);
    ecs_entities_t to_add = {
        .array = &e,
        .count = 1
    };

    ecs_entity_t cur = stage->scope;
    stage->scope = scope;

    if (scope) {
        stage->scope_table = ecs_table_traverse_add(
            world, &world->store.root, &to_add, NULL);
    } else {
        stage->scope_table = &world->store.root;
    }

    return cur;
}

ecs_entity_t ecs_get_scope(
    const ecs_world_t *world)
{
    const ecs_stage_t *stage = ecs_stage_from_readonly_world(world);
    return stage->scope;
}

int32_t ecs_get_child_count(
    const ecs_world_t *world,
    ecs_entity_t parent)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    world = ecs_get_world(world);

    int32_t count = 0;

    ecs_id_record_t *r = ecs_get_id_record(world, ecs_pair(EcsChildOf, parent));
    if (r && r->table_index) {
        ecs_map_iter_t it = ecs_map_iter(r->table_index);
        ecs_table_record_t *tr;
        while ((tr = ecs_map_next(&it, ecs_table_record_t, NULL))) {
            count += ecs_table_count(tr->table);
        }
    }

    return count;
}

ecs_iter_t ecs_scope_iter_w_filter(
    ecs_world_t *iter_world,
    ecs_entity_t parent,
    ecs_filter_t *filter)
{
    ecs_assert(iter_world != NULL, ECS_INTERNAL_ERROR, NULL);
    const ecs_world_t *world = (ecs_world_t*)ecs_get_world(iter_world);
    ecs_iter_t it = {
        .world = iter_world
    };

    ecs_id_record_t *r = ecs_get_id_record(world, ecs_pair(EcsChildOf, parent));
    if (r && r->table_index) {
        it.iter.parent.tables = ecs_map_iter(r->table_index);
        it.table_count = ecs_map_count(r->table_index);
        if (filter) {
            it.iter.parent.filter = *filter;
        }
    }

    return it;
}

ecs_iter_t ecs_scope_iter(
    ecs_world_t *iter_world,
    ecs_entity_t parent)
{
    return ecs_scope_iter_w_filter(iter_world, parent, NULL);
}

bool ecs_scope_next(
    ecs_iter_t *it)
{
    ecs_scope_iter_t *iter = &it->iter.parent;
    ecs_map_iter_t *tables = &iter->tables;
    ecs_filter_t filter = iter->filter;
    ecs_table_record_t *tr;
    while ((tr = ecs_map_next(tables, ecs_table_record_t, NULL))) {
        ecs_table_t *table = tr->table;
        ecs_assert(table != NULL, ECS_INTERNAL_ERROR, NULL);

        iter->index ++;

        ecs_data_t *data = ecs_table_get_data(table);
        if (!data) {
            continue;
        }

        it->count = ecs_table_count(table);
        if (!it->count) {
            continue;
        }

        if (filter.include || filter.exclude) {
            if (!ecs_table_match_filter(it->world, table, &filter)) {
                continue;
            }
        }

        iter->table.table = table;
        it->table = &iter->table;
        it->table_columns = data->columns;
        it->count = ecs_table_count(table);
        it->entities = ecs_vector_first(data->entities, ecs_entity_t);

        return true;
    }

    return false;    
}

const char* ecs_set_name_prefix(
    ecs_world_t *world,
    const char *prefix)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INTERNAL_ERROR, NULL);

    const char *old_prefix = world->name_prefix;
    world->name_prefix = prefix;
    return old_prefix;
}

ecs_entity_t ecs_add_path_w_sep(
    ecs_world_t *world,
    ecs_entity_t entity,
    ecs_entity_t parent,
    const char *path,
    const char *sep,
    const char *prefix)
{
    ecs_assert(world != NULL, ECS_INTERNAL_ERROR, NULL);

    if (!sep) {
        sep = ".";
    }    

    if (!path) {
        if (!entity) {
            entity = ecs_new_id(world);
        }

        if (parent) {
            ecs_add_pair(world, entity, EcsChildOf, entity);
        }

        return entity;
    }

    char buff[ECS_MAX_NAME_LENGTH];
    const char *ptr = path;

    parent = get_parent_from_path(world, parent, &path, prefix, entity == 0);

    ecs_entity_t cur = parent;

    while ((ptr = path_elem(ptr, buff, sep))) {
        ecs_entity_t e = ecs_lookup_child(world, cur, buff);
        if (!e) {
            char *name = ecs_os_strdup(buff);

            /* If this is the last entity in the path, use the provided id */
            if (entity && !path_elem(ptr, buff, sep)) {
                e = entity;
            }

            if (!e) {
                e = ecs_new_id(world);
            }
            
            ecs_set(world, e, EcsName, {
                .value = name,
                .alloc_value = name
            });

            ecs_os_free(name);

            if (cur) {
                ecs_add_pair(world, e, EcsChildOf, cur);
            }
        }

        cur = e;
    }

    return cur;
}

ecs_entity_t ecs_new_from_path_w_sep(
    ecs_world_t *world,
    ecs_entity_t parent,
    const char *path,
    const char *sep,
    const char *prefix)
{
    if (!sep) {
        sep = ".";
    }

    return ecs_add_path_w_sep(world, 0, parent, path, sep, prefix);
}

void ecs_use(
    ecs_world_t *world,
    ecs_entity_t entity,
    const char *name)
{
    ecs_assert(world != NULL, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(world->magic == ECS_WORLD_MAGIC, ECS_INVALID_PARAMETER, NULL);

    ecs_assert(entity != 0, ECS_INVALID_PARAMETER, NULL);
    ecs_assert(name != NULL, ECS_INVALID_PARAMETER, NULL);
    
    ecs_stage_t *stage = ecs_stage_from_world(&world);
    ecs_assert(stage->scope == 0 , ECS_INVALID_PARAMETER, NULL);
    ecs_assert(find_as_alias(world, name) == 0, ECS_ALREADY_DEFINED, NULL);
    (void)stage;
    
    ecs_alias_t *al = ecs_vector_add(&world->aliases, ecs_alias_t);
    al->name = ecs_os_strdup(name);
    al->entity = entity;
}
