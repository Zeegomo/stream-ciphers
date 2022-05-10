
#include "pmsis.h"
#include <bsp/bsp.h>


#define HOTTING 1
#define REPEAT  3
#define STACK_SIZE      2048
#define LEN             (14336*5 -1)
#define BUF_LEN             (14336*3)


PI_L2 char data[LEN];
PI_L1 char buf[BUF_LEN];
PI_L2 char data2[LEN];
PI_L2 char data3[LEN];
PI_L1 char key[32];

void encrypt(char *data, size_t len, char *key, char *alloc, size_t alloc_len);

void encrypt_serial(char *data, size_t len, char *key);

void encrypt_serial_orig(char *data, size_t len, char *key);

#define INIT_STATS()  

#define ENTER_STATS_LOOP()  \
    unsigned long _cycles = 0; \
    unsigned long _instr = 0; \
    unsigned long _active = 0; \
    unsigned long _ldext = 0; \
    unsigned long _tcdmcont = 0; \
    unsigned long _ld = 0; \
    unsigned long _st = 0; \
    unsigned long _ldstall = 0; \
    unsigned long _imiss = 0; \
    for(int _k=0; _k<HOTTING+REPEAT; _k++) { \
      pi_perf_conf((1<<PI_PERF_CYCLES) | (1<<PI_PERF_INSTR) | (1<<PI_PERF_ACTIVE_CYCLES) | (1<<PI_PERF_LD) | (1<<PI_PERF_ST) | (1<<PI_PERF_LD_STALL) | (1<<PI_PERF_IMISS) );


#define START_STATS()  \
    pi_perf_reset(); \
    pi_perf_start();

#define STOP_STATS() \
     pi_perf_stop(); \
     if (_k >= HOTTING) \
      { \
        _cycles   += pi_perf_read (PI_PERF_CYCLES); \
        _instr    += pi_perf_read (PI_PERF_INSTR); \
    	_active   += pi_perf_read (PI_PERF_ACTIVE_CYCLES); \
        _ld    += pi_perf_read (PI_PERF_LD); \
        _st    += pi_perf_read (PI_PERF_ST); \
    	_ldstall  += pi_perf_read (PI_PERF_LD_STALL); \
        _imiss    += pi_perf_read (PI_PERF_IMISS); \
      }

#define EXIT_STATS_LOOP()  \
    } \
    printf("[%d] total cycles = %lu\n", 0, _cycles/REPEAT); \
    printf("[%d] instructions = %lu\n", 0, _instr/REPEAT); \
    printf("[%d] active cycles = %lu\n", 0, _active/REPEAT); \
    printf("[%d] loads = %lu\n", 0, _ld/REPEAT); \
    printf("[%d] stores = %lu\n", 0, _st/REPEAT); \
    printf("[%d] LD stalls = %lu\fn", 0, _ldstall/REPEAT); \
    printf("[%d] I$ misses = %lu\n", 0, _imiss/REPEAT);


// Cluster entry pointd
static void cluster_entry(void *arg)
{
//  // init performance counters
     INIT_STATS();

//   // executing the code multiple times to perform average statistics
    ENTER_STATS_LOOP();
    for(int i = 0; i < LEN; i++){
      data[i] = 0;
      data2[i] = 0;
      data3[i]= 0;
  }
    START_STATS();
    
    encrypt(data, LEN, key, buf, BUF_LEN);
    STOP_STATS();

  // end of the performance statistics loop
    EXIT_STATS_LOOP();
}


int main()
{
  struct pi_device cluster_dev = {0};
  struct pi_cluster_conf conf;
  struct pi_cluster_task cluster_task = {0};

  // task parameters allocation
  pi_cluster_task(&cluster_task, cluster_entry, NULL);

  // [OPTIONAL] specify the stack size for the task
  cluster_task.stack_size = STACK_SIZE;
  cluster_task.slave_stack_size = STACK_SIZE;

  // open the cluster
  pi_cluster_conf_init(&conf);
  pi_open_from_conf(&cluster_dev, &conf);
  if (pi_cluster_open(&cluster_dev))
  {
    printf("ERROR: Cluster not working\n");
    return -1;
  }
  for(int i = 0; i < 32; i++)
    key[i] = 0;

  for(int i = 0; i < LEN; i++){
      data[i] = 0;
      data2[i] = 0;
      data3[i]= 0;
  }

  // INIT_STATS();
  // ENTER_STATS_LOOP();
  // START_STATS();
  pi_cluster_send_task_to_cl(&cluster_dev, &cluster_task);
  // STOP_STATS();
  // EXIT_STATS_LOOP();
  printf("encrypt serial\n", data[0], data[LEN-1]);
  
  // pi_cluster_task(&cluster_task, cluster_entry3, NULL);
//   // pi_cluster_send_task_to_cl(&cluster_dev, &cluster_task);
//    {INIT_STATS();

// // //   // executing the code multiple times to perform average statistics
//     ENTER_STATS_LOOP();
//     START_STATS();
    encrypt_serial(data2, LEN, key);
//     STOP_STATS();
//     EXIT_STATS_LOOP();}


//     {INIT_STATS();

// // //   // executing the code multiple times to perform average statistics
//     ENTER_STATS_LOOP();
//     START_STATS();
//     encrypt_serial_orig(data3, LEN, key);
//     STOP_STATS();
//     EXIT_STATS_LOOP();}


  for(int i = 0; i < LEN; i++){
      if (data[i] !=data2[i]) {
          printf("WRONG %d %d %d %d\n", i, data[i], data2[i], data3[i]);
          break;
      }
  }

  // closing the cluster
  pi_cluster_close(&cluster_dev);
    


  return 0;
}