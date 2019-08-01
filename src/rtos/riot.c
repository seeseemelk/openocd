/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <target/target.h>

#include "stdio.h"
#include "rtos.h"
#include "log.h"
#include "rtos_riot_stackings.h"
#include "rtos_standard_stackings.h"

struct riot_params {
	const struct rtos_register_stacking *stacking;
	uint32_t thread_count;
	uint32_t *thread_ptrs;
};

static const char * const riot_symbol_list[] = {
	"sched_num_threads",
	"sched_threads",
	NULL
};

enum riot_symbol_values {
	RIOT_VAL_sched_num_threads = 0,
	RIOT_VAL_sched_threads,
	RIOT_VAL_COUNT
};

// see RIOT/core/include/thread.h
typedef enum {
    STATUS_STOPPED,                 /**< has terminated                       */
    STATUS_SLEEPING,                /**< sleeping                             */
    STATUS_MUTEX_BLOCKED,           /**< waiting for a locked mutex           */
    STATUS_RECEIVE_BLOCKED,         /**< waiting for a message                */
    STATUS_SEND_BLOCKED,            /**< waiting for message to be delivered  */
    STATUS_REPLY_BLOCKED,           /**< waiting for a message response       */
    STATUS_FLAG_BLOCKED_ANY,        /**< waiting for any flag from flag_mask  */
    STATUS_FLAG_BLOCKED_ALL,        /**< waiting for all flags in flag_mask   */
    STATUS_MBOX_BLOCKED,            /**< waiting for get/put on mbox          */
    STATUS_COND_BLOCKED,            /**< waiting for a condition variable     */
    STATUS_RUNNING,                 /**< currently running                    */
    STATUS_PENDING,                 /**< waiting to be scheduled to run       */
    STATUS_NUMOF                    /**< number of supported thread states    */
} thread_state_t;

// riotbuild.h settings
#define MODULE_CORE
#define MODULE_CORE_MSG
#define DEVELHELP

/**
 * @brief circular integer buffer structure
 */
typedef struct {
    unsigned int read_count;    /**< number of (successful) read accesses */
    unsigned int write_count;   /**< number of (successful) write accesses */
    unsigned int mask;          /**< Size of buffer -1, i.e. mask of the bits */
} cib_t;

typedef struct list_node {
	uint32_t next;     /**< pointer to next list entry */
} list_node_t;

// see RIOT/core/include/thread.h
struct _thread {
    uint32_t sp;                       /**< thread's stack pointer         */
    uint8_t status;                    /**< thread's status                */
    uint8_t priority;                  /**< thread's priority              */

    int16_t pid;                    /**< thread's process id            */

#if defined(MODULE_CORE_THREAD_FLAGS) || defined(DOXYGEN)
    thread_flags_t flags;           /**< currently set flags            */
#endif

    list_node_t rq_entry;                 /**< run queue entry                */

#if defined(MODULE_CORE_MSG) || defined(MODULE_CORE_THREAD_FLAGS) \
    || defined(MODULE_CORE_MBOX) || defined(DOXYGEN)
    uint32_t wait_data;                /**< used by msg, mbox and thread
                                         flags                          */
#endif
#if defined(MODULE_CORE_MSG) || defined(DOXYGEN)
    list_node_t msg_waiters;        /**< threads waiting for their message
                                         to be delivered to this thread
                                         (i.e. all blocked sends)       */
    cib_t msg_queue;                /**< index of this [thread's message queue]
                                         (thread_t::msg_array), if any  */
    uint32_t msg_array;               /**< memory holding messages sent
                                         to this thread's message queue */
#endif
#if defined(DEVELHELP) || defined(SCHED_TEST_STACK) \
    || defined(MODULE_MPU_STACK_GUARD) || defined(DOXYGEN)
    uint32_t stack_start;              /**< thread's stack start address   */
#endif
#if defined(DEVELHELP) || defined(DOXYGEN)
    uint32_t name;               /**< thread's name                  */
    int stack_size;                 /**< thread's stack size            */
#endif
#ifdef HAVE_THREAD_ARCH_T
    thread_arch_t arch;             /**< architecture dependent part    */
#endif
} __attribute__((packed));

static bool riot_detect_rtos(struct target *target)
{
	enum riot_symbol_values sym;

	if (!target || !target->rtos || !target->rtos->symbols)
		return false;

	for (sym = RIOT_VAL_sched_num_threads;
		 sym < RIOT_VAL_COUNT; sym++) {
		if (target->rtos->symbols[sym].address) {
			LOG_DEBUG("RIOT: Symbol \"%s\" found",
					riot_symbol_list[sym]);
		} else {
			LOG_ERROR("RIOT: Symbol \"%s\" missing",
					riot_symbol_list[sym]);
			return false;
		}
	}

	return true;
}

static int riot_create(struct target *target)
{
	struct riot_params *params = calloc(1, sizeof(struct riot_params));
	params->stacking = &rtos_standard_Cortex_M4F_stacking;

	target->rtos->rtos_specific_params = params;

	target->rtos->current_thread = 0;
	target->rtos->thread_details = NULL;
	target->rtos->thread_count = 0;

	return 0;
}

static char *alloc_info_str(thread_state_t status)
{
	char *buf = malloc(64);
	switch (status)
	{
	case STATUS_STOPPED:
		strcpy(buf, "Stopped");
		break;
	case STATUS_SLEEPING:
		strcpy(buf, "Sleeping");
		break;
	case STATUS_MUTEX_BLOCKED:
		strcpy(buf, "Blocked on mutex");
		break;
	case STATUS_RECEIVE_BLOCKED:
		strcpy(buf, "Waiting for message");
		break;
	case STATUS_SEND_BLOCKED:
		strcpy(buf, "Sending message");
		break;
	case STATUS_REPLY_BLOCKED:
		strcpy(buf, "Replying to message");
		break;
	case STATUS_FLAG_BLOCKED_ANY:
		strcpy(buf, "Waiting for any flag from flag_mask");
		break;
	case STATUS_FLAG_BLOCKED_ALL:
		strcpy(buf, "Waiting for all flags in flag_mask");
		break;
	case STATUS_MBOX_BLOCKED:
		strcpy(buf, "Blocked on get/put on mbox");
		break;
	case STATUS_COND_BLOCKED:
		strcpy(buf, "Blocked on condition variable");
		break;
	case STATUS_RUNNING:
		strcpy(buf, "Running");
		break;
	case STATUS_PENDING:
		strcpy(buf, "Pending");
		break;
	default:
		snprintf(buf, 64, "Invalid status: %d", status);
		break;
	}
	return buf;
}

static int riot_update_threads(struct rtos *rtos)
{
	struct riot_params *params = rtos->rtos_specific_params;
	int32_t thread_count;
	int ret;

	if (rtos->symbols == NULL) {
		LOG_ERROR("No symbols for RIOT");
		return -3;
	}

	ret = target_read_u32(rtos->target,
			rtos->symbols[RIOT_VAL_sched_num_threads].address,
			(uint32_t *)&thread_count);
	if (ret != ERROR_OK) {
		LOG_ERROR("Failed to get thread count");
		return ret;
	}

	rtos_free_threadlist(rtos);
	rtos->thread_count = thread_count;
	rtos->thread_details = malloc(sizeof(struct thread_detail) * thread_count);

	// Read the list of thread pointers.
	params->thread_ptrs = realloc(params->thread_ptrs, sizeof(uint32_t) * thread_count);
	ret = target_read_buffer(rtos->target,
			rtos->symbols[RIOT_VAL_sched_threads].address,
			4 * (thread_count + 1),
			(uint8_t *)params->thread_ptrs);
	if (ret != ERROR_OK) {
		LOG_ERROR("Failed to read thread details");
		return ret;
	}

	for (int i = 0; i < rtos->thread_count; i++) {
		struct thread_detail *thread;
		struct _thread thread_info;

		thread = rtos->thread_details + i;

		ret = target_read_buffer(rtos->target,
				params->thread_ptrs[i + 1],
				sizeof(struct _thread),
				(uint8_t *)&thread_info);
		if (ret != ERROR_OK) {
			LOG_ERROR("Failed to read thread buffer");
			continue;
		}


		thread->exists = true;
		thread->threadid = thread_info.pid;

		char *name_buf = malloc(64);
		ret = target_read_buffer(rtos->target,
				(target_addr_t) thread_info.name,
				64,
				(unsigned char *)name_buf);
		if (ret != ERROR_OK) {
			LOG_ERROR("Failed to read thread name");
			strcpy(name_buf, "Unnamed Thread");
		}
		thread->thread_name_str = name_buf;
		thread->extra_info_str = alloc_info_str(thread_info.status);

		if (thread_info.status == STATUS_RUNNING) {
			rtos->current_thread = thread->threadid;
			rtos->current_threadid = i;
		}
	}

	return ERROR_OK;
}

static int riot_get_thread_reg_list(struct rtos *rtos,
		threadid_t threadid,
		struct rtos_reg **reg_list,
		int *num_regs)
{
	struct riot_params *params = rtos->rtos_specific_params;
	int ret;

	if (rtos->symbols == NULL) {
		LOG_ERROR("No symbols for RIOT");
		return -3;
	}

	// Read thread count.
	int32_t thread_count;
	ret = target_read_u32(rtos->target,
			rtos->symbols[RIOT_VAL_sched_num_threads].address,
			(uint32_t *)&thread_count);
	if (ret != ERROR_OK) {
		LOG_ERROR("Failed to get thread count");
		return ret;
	}

	// Read the list of thread pointers.
	uint32_t thread_ptrs[thread_count];
	ret = target_read_buffer(rtos->target,
			rtos->symbols[RIOT_VAL_sched_threads].address,
			4 * (thread_count + 1),
			(uint8_t *)thread_ptrs);
	if (ret != ERROR_OK) {
		LOG_ERROR("Failed to read thread details");
		return ret;
	}

	// Find the correct thread.
	for (int i = 0; i < rtos->thread_count; i++) {
		struct _thread thread_info;

		ret = target_read_buffer(rtos->target,
				thread_ptrs[i + 1],
				sizeof(struct _thread),
				(uint8_t *)&thread_info);
		if (ret != ERROR_OK) {
			LOG_ERROR("Failed to read thread buffer");
			continue;
		}

		if (thread_info.pid == threadid) {
			// Read thread info.
			return rtos_generic_stack_read(
					rtos->target,
					params->stacking,
					thread_info.sp,
					reg_list,
					num_regs
			);
		}
	}

	LOG_ERROR("Thread not found");
	return ERROR_FAIL;
}

static int riot_get_symbol_list_to_lookup(symbol_table_elem_t *symbol_list[])
{
	size_t s;

	*symbol_list = calloc(ARRAY_SIZE(riot_symbol_list),
				  sizeof(symbol_table_elem_t));
	if (!(*symbol_list)) {
		LOG_ERROR("RIOT: out of memory");
		return ERROR_FAIL;
	}

	for (s = 0; s < ARRAY_SIZE(riot_symbol_list); s++)
		(*symbol_list)[s].symbol_name = riot_symbol_list[s];

	return ERROR_OK;
}

struct rtos_type riot_rtos = {
	.name = "riot",
	.detect_rtos = riot_detect_rtos,
	.create = riot_create,
	.update_threads = riot_update_threads,
	.get_thread_reg_list = riot_get_thread_reg_list,
	.get_symbol_list_to_lookup = riot_get_symbol_list_to_lookup
};
