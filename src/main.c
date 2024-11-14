#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/thread_status.h>
#include <sys/errno.h>
#include <sys/wait.h>

#define MAX_BREAKPOINTS 100
#define INSTRUCTION_SIZE 4

struct breakpoint
{
    mach_vm_address_t address;
    uint32_t original_instruction;
    bool enabled;
};

struct except_handler
{
    mach_port_t exception_port;
    mach_port_t thread;
    mach_port_t task;
    bool is_attached;
    pid_t target_pid;
};

struct except_msg
{
    mach_msg_header_t header;
    NDR_record_t ndr;
    exception_type_t exception;
    mach_msg_type_number_t code_count;
    integer_t code[2];
    int flavor;
    mach_msg_type_number_t old_state_count;
    natural_t old_state[144];
};

struct except_reply
{
    mach_msg_header_t header;
    NDR_record_t ndr;
    kern_return_t ret_code;
};

static struct breakpoint breakpoints[MAX_BREAKPOINTS];
static int num_breakpoints = 0;

static void cleanup_handler(struct except_handler* handler)
{
    if (handler->is_attached)
    {
        if (handler->task != MACH_PORT_NULL)
        {
            task_set_exception_ports(handler->task, EXC_MASK_BREAKPOINT,
                                   MACH_PORT_NULL, EXCEPTION_DEFAULT, 0);
        }
        if (handler->target_pid > 0)
        {
            kill(handler->target_pid, SIGTERM);
            waitpid(handler->target_pid, NULL, 0);
        }
    }

    if (handler->exception_port != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), handler->exception_port);

    handler->is_attached = false;
    handler->exception_port = MACH_PORT_NULL;
    handler->task = MACH_PORT_NULL;
}

static kern_return_t setup_exception_handler(struct except_handler* handler, const task_t task)
{
    handler->is_attached = false;
    handler->task = task;
    handler->exception_port = MACH_PORT_NULL;

    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                                        &handler->exception_port);
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "Failed to allocate port: %s\n", mach_error_string(kr));
        return kr;
    }

    kr = mach_port_insert_right(mach_task_self(), handler->exception_port,
                               handler->exception_port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "Failed to insert right: %s\n", mach_error_string(kr));
        cleanup_handler(handler);
        return kr;
    }

    kr = task_set_exception_ports(task, EXC_MASK_BREAKPOINT, handler->exception_port,
                                EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
                                ARM_THREAD_STATE64);
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "Failed to set exception ports: %s\n", mach_error_string(kr));
        cleanup_handler(handler);
        return kr;
    }

    handler->is_attached = true;
    return KERN_SUCCESS;
}

static kern_return_t set_breakpoint(const task_t task, const mach_vm_address_t address)
{
    if (task == MACH_PORT_NULL || address == 0)
        return KERN_INVALID_ARGUMENT;

    if (num_breakpoints >= MAX_BREAKPOINTS)
    {
        fprintf(stderr, "Maximum breakpoints reached\n");
        return KERN_FAILURE;
    }

    uint32_t brk = 0xD4200000;  // BRK #0
    uint32_t original;
    mach_vm_size_t size;

    kern_return_t kr = mach_vm_read_overwrite(task, address, INSTRUCTION_SIZE,
                                            (mach_vm_address_t)&original, &size);
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "Failed to read memory: %s\n", mach_error_string(kr));
        return kr;
    }

    kr = mach_vm_protect(task, address, INSTRUCTION_SIZE, FALSE,
                        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "Failed to set memory protection: %s\n", mach_error_string(kr));
        return kr;
    }

    kr = mach_vm_write(task, address, (vm_offset_t)&brk, INSTRUCTION_SIZE);
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "Failed to write breakpoint: %s\n", mach_error_string(kr));
        return kr;
    }

    breakpoints[num_breakpoints].address = address;
    breakpoints[num_breakpoints].original_instruction = original;
    breakpoints[num_breakpoints].enabled = true;
    num_breakpoints++;

    return KERN_SUCCESS;
}

static kern_return_t restore_breakpoint(const task_t task, const mach_vm_address_t address)
{
    if (task == MACH_PORT_NULL || address == 0)
        return KERN_INVALID_ARGUMENT;

    for (int i = 0; i < num_breakpoints; i++)
    {
        if (breakpoints[i].address == address && breakpoints[i].enabled)
        {
            const kern_return_t kr = mach_vm_write(task, address,
                                                   (vm_offset_t)&breakpoints[i].original_instruction,
                                                   INSTRUCTION_SIZE);
            if (kr != KERN_SUCCESS)
            {
                fprintf(stderr, "Failed to restore instruction: %s\n",
                        mach_error_string(kr));
                return kr;
            }
            breakpoints[i].enabled = false;
            return KERN_SUCCESS;
        }
    }
    return KERN_FAILURE;
}

extern int task_for_pid_np(mach_port_name_t target_tport, int pid, mach_port_t *t);

static kern_return_t handle_exception(const struct except_handler* handler)
{
    struct except_msg msg = {0};
    struct except_reply reply = {0};

    mach_msg_return_t mr = mach_msg(&msg.header, MACH_RCV_MSG, 0, sizeof(msg),
                                   handler->exception_port, MACH_MSG_TIMEOUT_NONE,
                                   MACH_PORT_NULL);
    if (mr != MACH_MSG_SUCCESS)
    {
        fprintf(stderr, "Failed to receive exception message: %s\n",
                mach_error_string(mr));
        return mr;
    }

    if (msg.exception == EXC_BREAKPOINT)
    {
        arm_thread_state64_t state;
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;

        kern_return_t kr = thread_get_state(msg.header.msgh_remote_port,
                                          ARM_THREAD_STATE64,
                                          (thread_state_t)&state,
                                          &count);
        if (kr != KERN_SUCCESS)
        {
            fprintf(stderr, "Failed to get thread state: %s\n",
                    mach_error_string(kr));
            return kr;
        }

        printf("Breakpoint hit at 0x%llx\n", state.__pc);

        kr = restore_breakpoint(handler->task, state.__pc);
        if (kr != KERN_SUCCESS)
        {
            fprintf(stderr, "Failed to restore breakpoint\n");
            return kr;
        }

        state.__pc -= 4;
        kr = thread_set_state(msg.header.msgh_remote_port,
                             ARM_THREAD_STATE64,
                             (thread_state_t)&state,
                             ARM_THREAD_STATE64_COUNT);
        if (kr != KERN_SUCCESS)
        {
            fprintf(stderr, "Failed to set thread state: %s\n",
                    mach_error_string(kr));
            return kr;
        }
    }

    reply.header = msg.header;
    reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(msg.header.msgh_bits), 0);
    reply.header.msgh_size = sizeof(reply);
    reply.header.msgh_remote_port = msg.header.msgh_remote_port;
    reply.header.msgh_local_port = MACH_PORT_NULL;
    reply.header.msgh_id = msg.header.msgh_id + 100;
    reply.ndr = NDR_record;
    reply.ret_code = KERN_SUCCESS;

    return mach_msg(&reply.header, MACH_SEND_MSG, sizeof(reply), 0,
                   MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

static pid_t spawn_target_process(const char* filepath)
{
    if (!filepath)
        return -1;

    pid_t pid;
    char *const argv[] = {(char*)filepath, NULL};
    char *const envp[] = {NULL};

    int status = posix_spawn(&pid, filepath, NULL, NULL, argv, envp);
    if (status != 0)
    {
        fprintf(stderr, "Failed to spawn process: %s\n", strerror(status));
        return -1;
    }

    usleep(100000);
    return pid;
}

int main(const int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <executable_path> <address>\n", argv[0]);
        return 1;
    }

    if (geteuid() != 0)
    {
        fprintf(stderr, "This program requires root privileges\n");
        return 1;
    }

    if (access(argv[1], X_OK) != 0)
    {
        fprintf(stderr, "File %s is not executable or does not exist\n", argv[1]);
        return 1;
    }

    char *end_ptr;
    errno = 0;
    const mach_vm_address_t addr = strtoull(argv[2], &end_ptr, 16);
    if (errno != 0 || end_ptr == argv[2] || addr == 0)
    {
        fprintf(stderr, "Invalid address\n");
        return 1;
    }

    const pid_t target_pid = spawn_target_process(argv[1]);
    if (target_pid < 0)
        return 1;

    task_t task = MACH_PORT_NULL;
    printf("Attempting to attach to process with PID: %d\n", target_pid);
    kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &task);
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "Failed to attach to process: %s\n", mach_error_string(kr));
        kill(target_pid, SIGTERM);
        return 1;
    }

    struct except_handler handler = {0};
    handler.target_pid = target_pid;
    kr = setup_exception_handler(&handler, task);
    if (kr != KERN_SUCCESS)
    {
        kill(target_pid, SIGTERM);
        return 1;
    }

    kr = set_breakpoint(task, addr);
    if (kr != KERN_SUCCESS)
    {
        cleanup_handler(&handler);
        return 1;
    }

    printf("Debugger attached to process %s. Breakpoint set at 0x%llx\n", argv[1], addr);
    printf("Waiting for breakpoint...\n");

    while (true)
    {
        kr = handle_exception(&handler);
        if (kr != KERN_SUCCESS)
            break;
    }

    cleanup_handler(&handler);
    return 0;
}
