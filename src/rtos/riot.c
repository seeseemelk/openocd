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

#include "target/target.h"
#include "target/register.h"
#include "stdio.h"
#include "rtos.h"
#include "log.h"
#include "rtos_riot_stackings.h"
#include "binarybuffer.h"
#include "types.h"

#include <stdbool.h>

#define IRQ_THREAD_ID 100
#define NO_THREAD_ID 101

static const char * const riot_symbol_list[] = {
	"sched_num_threads",
	"sched_threads",
	"built_with_develhelp",
	"max_threads",
	"_tcb_name_offset",
	NULL
};

enum riot_symbol_values {
	RIOT_VAL_sched_num_threads = 0,
	RIOT_VAL_sched_threads,
	RIOT_VAL_develhelp,
	RIOT_VAL_max_threads,
	RIOT_VAL_tcb_name_offset,
	RIOT_VAL_COUNT
};

// see RIOT/core/include/thread.h
typedef enum {
    STATUS_STOPPED,                 /**< has terminated                       */
    STATUS_ZOMBIE,                  /**< has terminated & keeps thread's thread_t */
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
//#define DEVELHELP

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

struct thread_info {
	uint32_t sp;
	uint8_t status;
	uint8_t priority;
	int16_t pid;
	uint32_t name;
};

// see RIOT/core/include/thread.h
struct _thread_with_develhelp {
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
    uint32_t stack_start;
    uint32_t name;               /**< thread's name                  */
    int stack_size;                 /**< thread's stack size            */
#ifdef HAVE_THREAD_ARCH_T
    thread_arch_t arch;             /**< architecture dependent part    */
#endif
} __attribute__((packed));

struct _thread_without_develhelp {
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
#ifdef HAVE_THREAD_ARCH_T
    thread_arch_t arch;             /**< architecture dependent part    */
#endif
} __attribute__((packed));


struct riot_params {
	const struct rtos_register_stacking *stacking;
	uint32_t thread_count;
	uint32_t max_threads;
	uint32_t *thread_ptrs;
	struct thread_info *thread_infos;
	bool inside_irq;
	bool develhelp;
	uint32_t register_sp;
	uint32_t register_psp;
};

static bool is_develhelp_symbol(const char* symbol)
{
	return (strcmp("_tcb_name_offset", symbol) != 0)
		|| (strcmp("built_with_develhelp", symbol) != 0);
}

static bool riot_detect_rtos(struct target *target)
{
	enum riot_symbol_values sym;

	if (!target || !target->rtos || !target->rtos->symbols)
		return false;

	for (sym = RIOT_VAL_sched_num_threads;
		 sym < RIOT_VAL_COUNT; sym++) {
		if (!is_develhelp_symbol(target->rtos->symbols[sym].symbol_name)) {
			if (target->rtos->symbols[sym].address) {
				LOG_DEBUG("RIOT: Symbol \"%s\" found",
						riot_symbol_list[sym]);
			} else {
				LOG_ERROR("RIOT: Symbol \"%s\" missing",
						riot_symbol_list[sym]);
				return false;
			}
		}
	}

	return true;
}

static int riot_create(struct target *target)
{
	struct riot_params *params = malloc(sizeof(struct riot_params));
	memset(params, 0, sizeof(struct riot_params));
	params->stacking = &rtos_riot_cortex_m34_stacking;

	target->rtos->rtos_specific_params = params;

	target->rtos->current_thread = 0;
	target->rtos->current_threadid = 1;
	target->rtos->thread_details = NULL;
	target->rtos->thread_count = 0;

	return 0;
}

static int riot_clean(struct target *target)
{
	struct riot_params *params = target->rtos->rtos_specific_params;

	free(params->thread_infos);
	params->thread_infos = NULL;

	free(params->thread_ptrs);
	params->thread_ptrs = NULL;

	rtos_free_threadlist(target->rtos);

	return 0;
}

static const char *describe_thread_status(thread_state_t status)
{
	switch (status)
	{
	case STATUS_STOPPED:
		return "stopped";
	case STATUS_ZOMBIE:
		return "zombie";
	case STATUS_SLEEPING:
		return "sleeping";
	case STATUS_MUTEX_BLOCKED:
		return "blocked on mutex";
	case STATUS_RECEIVE_BLOCKED:
		return "waiting for message";
	case STATUS_SEND_BLOCKED:
		return "sending message";
	case STATUS_REPLY_BLOCKED:
		return "replying to message";
	case STATUS_FLAG_BLOCKED_ANY:
		return "waiting for any flag from flag_mask";
	case STATUS_FLAG_BLOCKED_ALL:
		return "waiting for all flags in flag_mask";
	case STATUS_MBOX_BLOCKED:
		return "blocked on get/put on mbox";
	case STATUS_COND_BLOCKED:
		return "blocked on condition variable";
	case STATUS_RUNNING:
		return "running";
	case STATUS_PENDING:
		return "pending";
	default:
		return "INVALID STATUS";
	}
}

static char *alloc_info_str(struct thread_info *thread)
{
	char *buf = malloc(64);
	snprintf(buf, 64, "%s, priority: %u",
			describe_thread_status(thread->status),
			thread->priority
	);
	buf[63] = 0;
	return buf;
}

static int read_thread_info(struct riot_params *params, struct rtos *rtos, struct thread_info *thread_info, int thread_id)
{
	if (params->develhelp) {
		struct _thread_with_develhelp buf;
		int ret = target_read_buffer(rtos->target,
				params->thread_ptrs[thread_id],
				sizeof(struct _thread_with_develhelp),
				(uint8_t *)&buf);
		if (ret != ERROR_OK) {
			LOG_ERROR("Failed to read thread information");
			return ret;
		}

		thread_info->pid = buf.pid;
		thread_info->priority = buf.priority;
		thread_info->sp = buf.sp;
		thread_info->status = buf.status;
		thread_info->name = buf.name;
	} else {
		struct _thread_without_develhelp buf;
		int ret = target_read_buffer(rtos->target,
				params->thread_ptrs[thread_id],
				sizeof(struct _thread_with_develhelp),
				(uint8_t *)&buf);
		if (ret != ERROR_OK) {
			LOG_ERROR("Failed to read thread information");
			return ret;
		}

		thread_info->pid = buf.pid;
		thread_info->priority = buf.priority;
		thread_info->sp = buf.sp;
		thread_info->status = buf.status;
		thread_info->name = 0;
	}

	return ERROR_OK;
}

static int riot_update_threads(struct rtos *rtos)
{
	struct riot_params *params = rtos->rtos_specific_params;
	uint32_t thread_count;
	uint8_t max_threads;
	int ret;

	if (rtos->symbols == NULL) {
		LOG_ERROR("No symbols for RIOT");
		return -3;
	}

	// Check if we still need to perform the develhelp check.
	if (rtos->symbols[RIOT_VAL_develhelp].address == 0
			&& rtos->symbols[RIOT_VAL_tcb_name_offset].address == 0) {
		params->develhelp = false;
	} else {
		params->develhelp = true;
	}

	ret = target_read_u8(rtos->target,
			rtos->symbols[RIOT_VAL_max_threads].address, &max_threads);
	if (ret != ERROR_OK) {
		LOG_ERROR("Failed to get maximum number of threads");
		return ERROR_FAIL;
	}
	if (max_threads > 99) {
		LOG_ERROR("Target has an abnormal maximum number of threads");
		max_threads = 32;
	}

	ret = target_read_u32(rtos->target,
			rtos->symbols[RIOT_VAL_sched_num_threads].address, &thread_count);
	if (ret != ERROR_OK) {
		LOG_ERROR("Failed to get thread count");
		return ERROR_FAIL;
	}
	if (thread_count > 99) {
		LOG_ERROR("Target has an abnormal number of threads");
		thread_count = 0;
	}

	// Check if we are in an interrupt
	if (!target_was_examined(rtos->target)) {
		LOG_ERROR("Target was not yet examined");
		return ERROR_FAIL;
	}

	struct reg *reg = register_get_by_name(rtos->target->reg_cache, "control", true);
	if (reg == NULL) {
		LOG_ERROR("Could not find register 'control'");
		return ret;
	}
	uint32_t control_reg = buf_get_u32(reg->value, 0, 32);
	params->inside_irq = (control_reg & 2) == 0;

	// Do some housekeeping
	rtos_free_threadlist(rtos);
	if (thread_count == 0 || max_threads == 0) {
		LOG_ERROR("RIOT has a thread count of zero, threads might not yet be initialized");
		char* name = malloc(20);
		strcpy(name, "unknown");
		char* infostr = malloc(1);
		strcpy(infostr, "");

		rtos->thread_count = 1;
		rtos->thread_details = malloc(sizeof(struct thread_detail));
		rtos->thread_details->exists = true;
		rtos->thread_details->threadid = NO_THREAD_ID;
		rtos->thread_details->thread_name_str = name;
		rtos->thread_details->extra_info_str = infostr;
		rtos->current_thread = 0;
		rtos->current_threadid = NO_THREAD_ID;
		return 0;
	}
	rtos->thread_count = thread_count + (params->inside_irq?1:0);
	rtos->thread_details = malloc(sizeof(struct thread_detail) * rtos->thread_count);
	memset(rtos->thread_details, 0, sizeof(struct thread_detail) * rtos->thread_count);

	// Read the list of thread pointers
	params->thread_ptrs = realloc(params->thread_ptrs, sizeof(uint32_t) * max_threads);

	params->thread_infos = realloc(params->thread_infos, sizeof(struct thread_info) * thread_count);

	ret = target_read_buffer(rtos->target,
			rtos->symbols[RIOT_VAL_sched_threads].address + 4,
			sizeof(uint32_t) * max_threads,
			(uint8_t *)params->thread_ptrs);
	if (ret != ERROR_OK) {
		LOG_ERROR("Failed to read thread details");
		return ret;
	}

	uint32_t thread_id = -1;
	for (unsigned int i = 0; i < thread_count; i++) {
		do {
			thread_id++;
			if (thread_id >= max_threads) {
				LOG_ERROR("Thread structure is corrupt");
				thread_count = i;
				goto stopReadingThreads;
			}
		}
		while (params->thread_ptrs[thread_id] == 0);
		struct thread_detail *thread = rtos->thread_details + i;
		struct thread_info *thread_info = params->thread_infos + i;

		ret = read_thread_info(params, rtos, thread_info, thread_id);
		if (ret != ERROR_OK) {
			continue;
		}

		thread->exists = true;
		thread->threadid = thread_info->pid;

		char *name_buf = malloc(64);
		if (thread_info->name != 0) {
			ret = target_read_buffer(rtos->target,
					(target_addr_t) thread_info->name,
					64,
					(unsigned char *)name_buf);
			if (ret != ERROR_OK) {
				strcpy(name_buf, "unknown");
				LOG_ERROR("Failed to read thread name");
			}
			name_buf[63] = 0;
		} else {
			strcpy(name_buf, "unknown");
		}
		thread->thread_name_str = name_buf;

		thread->extra_info_str = alloc_info_str(thread_info);

		if (thread_info->status == STATUS_RUNNING || rtos->current_thread == 0) {
			rtos->current_thread = thread->threadid;
			rtos->current_threadid = thread_id;
		}
	}
	stopReadingThreads:

	if (params->inside_irq) {
		struct thread_detail *irq_thread = rtos->thread_details + rtos->thread_count - 1;

		char *info_buf = malloc(sizeof("IRQ"));
		strcpy(info_buf, "IRQ");
		irq_thread->extra_info_str = info_buf;
		irq_thread->exists = true;
		irq_thread->threadid = IRQ_THREAD_ID;

		char *name_buf = malloc(64);
		if (rtos->current_threadid != -1) {
			snprintf(name_buf, 64, "IRQ running on '%s'", rtos->thread_details[rtos->current_threadid].thread_name_str);
		} else {
			snprintf(name_buf, 64, "IRQ running on unknown thread");
		}
		name_buf[63] = 0;
		irq_thread->thread_name_str = name_buf;

		rtos->current_thread = irq_thread->threadid;
		rtos->current_threadid = thread_count;

		// Let's update the registers here so that we don't have to do it in riot_get_thread_reg_list.
		reg = register_get_by_name(rtos->target->reg_cache, "sp", true);
		if (reg == NULL) {
			LOG_ERROR("Could not find register 'sp'");
			return ERROR_FAIL;
		}
		params->register_sp = buf_get_u32(reg->value, 0, 32);

		reg = register_get_by_name(rtos->target->reg_cache, "psp", true);
		if (reg == NULL) {
			LOG_ERROR("Could not find register 'psp'");
			return ERROR_FAIL;
		}
		params->register_psp = buf_get_u32(reg->value, 0, 32);
	}

	return ERROR_OK;
}

static int riot_get_thread_reg_list(struct rtos *rtos,
		threadid_t threadid,
		struct rtos_reg **reg_list,
		int *num_regs)
{
	struct riot_params *params = rtos->rtos_specific_params;

	if (rtos->symbols == NULL) {
		return -3;
	}

	if (threadid == IRQ_THREAD_ID || threadid == NO_THREAD_ID) {
		// Fake IRQ thread.
		return rtos_generic_stack_read(
				rtos->target,
				params->stacking,
				params->register_sp,
				reg_list,
				num_regs
		);
	} else {
		// Find the correct thread.
		for (int i = 0; i < rtos->thread_count - (params->inside_irq?1:0); i++) {
			struct thread_info *thread_info = params->thread_infos + i;

			if (thread_info->pid == threadid) {
				uint32_t sp = thread_info->sp;

				if (params->inside_irq && thread_info->status == STATUS_RUNNING) {
					sp = params->register_psp - 0x24;
				}

				// Read thread info.
				return rtos_generic_stack_read(
						rtos->target,
						params->stacking,
						sp,
						reg_list,
						num_regs
				);
			}
		}

		LOG_ERROR("Thread not found");
		return ERROR_FAIL;
	}
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

	for (s = 0; s < ARRAY_SIZE(riot_symbol_list) - 1; s++)
	{
		symbol_table_elem_t* symbol = *symbol_list + s;
		symbol->symbol_name = riot_symbol_list[s];
		symbol->optional = is_develhelp_symbol(symbol->symbol_name);
	}

	return ERROR_OK;
}

struct rtos_type riot_rtos = {
	.name = "riot",
	.detect_rtos = riot_detect_rtos,
	.create = riot_create,
	.clean = riot_clean,
	.update_threads = riot_update_threads,
	.get_thread_reg_list = riot_get_thread_reg_list,
	.get_symbol_list_to_lookup = riot_get_symbol_list_to_lookup
};

struct rtos_type riot2_rtos = {
	.name = "RIOT",
	.detect_rtos = riot_detect_rtos,
	.create = riot_create,
	.clean = riot_clean,
	.update_threads = riot_update_threads,
	.get_thread_reg_list = riot_get_thread_reg_list,
	.get_symbol_list_to_lookup = riot_get_symbol_list_to_lookup
};
