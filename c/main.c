
#include "pmsis.h"
#include <bsp/bsp.h>


#define HOTTING 1
#define REPEAT  3
#define STACK_SIZE      2048
#define LEN             (131072)
#define BUF_LEN             (14336*3)


PI_L2 char data[LEN];
PI_L2 char data2[LEN];
PI_L1 char key[32];
PI_L1 char iv[12];
PI_L2 int lennn[1];
PI_L2 struct pi_device ram;
PI_L2 uint32_t ram_ptr;

void* cluster_init(pi_device_t** device);

void cluster_close(void* wrapper);

void encrypt(char *data, size_t len, char *key, char *iv, void* wrapper, pi_device_t* ram, int cipher);

void encrypt_serial_orig(char *data, size_t len, char *key, char *iv);

void test(uint8_t* a,  uint8_t* b, uint8_t* c, uint32_t len);

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
      pi_perf_conf((1<<PI_PERF_CYCLES) | (1<<PI_PERF_INSTR) | (1<<PI_PERF_ACTIVE_CYCLES) | (1<<PI_PERF_LD_EXT_CYC) | (1<<PI_PERF_ST_EXT_CYC) | (1<<PI_PERF_JR_STALL) | (1<<PI_PERF_TCDM_CONT) );


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
        _ld    += pi_perf_read (PI_PERF_LD_EXT_CYC); \
        _st    += pi_perf_read (PI_PERF_ST_EXT_CYC); \
    	_ldstall  += pi_perf_read (PI_PERF_JR_STALL); \
        _imiss    += pi_perf_read (PI_PERF_TCDM_CONT); \
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
    for(int i = 0; i < lennn[0]; i++){
      data[i] = 0;
  }
    START_STATS();
    encrypt(data, lennn[0], key, iv, arg, NULL, 0);
    STOP_STATS();

  // end of the performance statistics loop
    EXIT_STATS_LOOP();
}

static void cluster_entry_ram(void *arg)
{
//  // init performance counters
     //INIT_STATS();

//   // executing the code multiple times to perform average statistics
    //ENTER_STATS_LOOP();
  //   for(int i = 0; i < len; i++){
  //     data[i] = 0;
  //     data2[i] = 0;
  //     data3[i]= 0;
  // }
    // START_STATS();
    if (arg == NULL) {
    exit(2);
  }
    //chacha20_encrypt_ram((char *)ram_ptr, lennn[0], key, iv, arg, &ram);
    // STOP_STATS();

  // end of the performance statistics loop
    // EXIT_STATS_LOOP();
}


int main()
{
  //cluster_dev[0] = {0};
  struct pi_hyperram_conf ram_conf;
  struct pi_cluster_conf conf;
  struct pi_cluster_task cluster_task = {0};
  struct pi_cluster_task cluster_task_ram = {0};

  // [OPTIONAL] specify the stack size for the task
  cluster_task.stack_size = STACK_SIZE;
  cluster_task.slave_stack_size = STACK_SIZE;
  pi_device_t* cluster_dev;


  void* wrapper = cluster_init(&cluster_dev);

  printf("%p\n", wrapper);
  if (wrapper == NULL) {
    exit(2);
  }

  lennn[0] = LEN;
  for(int i = 0; i < 32; i++){
    key[i] = 0;
  }
  for(int j = 0; j < LEN; j++){
    data[j] = 0;
  }



  printf("iteration: %d\n", LEN);
  pi_cluster_task(&cluster_task, cluster_entry, wrapper);
    //pi_cluster_task(&cluster_task_ram, cluster_entry_ram, wrapper);
  pi_cluster_send_task_to_cl(cluster_dev, &cluster_task);
    //pi_cluster_send_task_to_cl(cluster_dev, &cluster_task_ram);

  // encrypt_serial_orig(data3, i, key, iv);
  
    // for(int j = 0; j < i; j++){
    //   if (data[j] !=data2[j] || data2[j] != data3[j] || data3[j] != data4[j]) {
    //     for (int o = 0; o < 10; o++){
    //       printf("wrong %d %d %d %d %d %d\n", i, j,  data[j+o], data2[j+o], data3[j+o], data4[j+o]);
    //     }
          
    //       exit(1);
    //   }
    // }
  

  printf("encrypt serial\n", data[0], data[LEN-1]);
  cluster_close(wrapper);

  return 0;
}