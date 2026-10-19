#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"

#define MAX_PAYLOAD 256

struct data_event {
  __u64 cgroup_id;
  __u32 pid;
  __u32 len;
  char payload[MAX_PAYLOAD];
};


struct {
  __uint(type , BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);

} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint(struct trace_event_raw_sys_enter *ctx) {
  unsigned int fd = (unsigned int)ctx->args[0];
  const char *user_bf = (const char *)ctx->args[1];
  size_t count = (size_t)ctx->args[2];

  if(fd!= 1 && fd != 2){
    return 0;
  }
  
  if(count < 2 ) {
    return 0;
  }

  struct data_event *e = bpf_ringbuf_reserve(&events, sizeof(struct data_event),0);
  if(!e){
    return 0;
  }


  e->cgroup_id = bpf_get_current_cgroup_id();
  e->pid = bpf_get_current_pid_tgid() >> 32;

  __u32 copy_len = count < MAX_PAYLOAD ? count :(MAX_PAYLOAD-1);
  e->len = copy_len;

  bpf_probe_read_user(e->payload, copy_len, user_bf);
  e->payload[copy_len] = '\0';

  bpf_ringbuf_submit(e,0);
  return 0;

}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
