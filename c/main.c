
#include "pmsis.h"
#include <bsp/bsp.h>


#define HOTTING 1
#define REPEAT  3
#define STACK_SIZE      2048
#define LEN             (100000)
#define BUF_LEN             (14336*3)


PI_L2 char data[LEN];
PI_L1 char buf[1];
PI_L2 char data2[LEN];
PI_L2 char data3[LEN];
PI_L2 char data4[LEN];
PI_L1 char key[32];
PI_L1 char iv[12];
PI_L2 int lennn[1];
PI_L2 pi_device_t cluster_dev[1];

PI_L2 pi_device_t cluster_dev[1];
PI_L2 struct pi_device ram;
PI_L2 uint32_t ram_ptr;

void* chacha20_cluster_init(pi_device_t *device);

void chacha20_cluster_close(void* wrapper);

void chacha20_encrypt(char *data, size_t len, char *key, char *iv, void* wrapper);

void chacha20_encrypt_ram(char *data, size_t len, char *key, char *iv, void* wrapper, pi_device_t* ram);

void encrypt_serial(char *data, size_t len, char *key, char *iv);

void encrypt_serial_orig(char *data, size_t len, char *key, char *iv);

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
     //INIT_STATS();

//   // executing the code multiple times to perform average statistics
    //ENTER_STATS_LOOP();
  //   for(int i = 0; i < len; i++){
  //     data[i] = 0;
  //     data2[i] = 0;
  //     data3[i]= 0;
  // }
    // START_STATS();
    chacha20_encrypt(data, lennn[0], key, iv, arg);
    // STOP_STATS();

  // end of the performance statistics loop
    // EXIT_STATS_LOOP();
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
    chacha20_encrypt_ram((char *)ram_ptr, lennn[0], key, iv, arg, &ram);
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

  pi_hyperram_conf_init(&ram_conf);
  pi_open_from_conf(&ram, &ram_conf);

  if (pi_ram_open(&ram))
    {
      printf("ERROR: Ram not working\n");
      return -1;
    }


  pi_ram_alloc(&ram, &ram_ptr, LEN);
  printf("%p\n", ram_ptr);

  // open the cluster
  pi_cluster_conf_init(&conf);
  pi_open_from_conf(cluster_dev, &conf);
  if (pi_cluster_open(cluster_dev))
  {
    printf("ERROR: Cluster not working\n");
    return -1;
  }
  for(int i = 0; i < 32; i++)
    key[i] = 0;

  lennn[0] = LEN;

  // INIT_STATS();
  // ENTER_STATS_LOOP();
  // START_STATS();
  // task parameters allocation

  void* wrapper = chacha20_cluster_init(cluster_dev);

  printf("%p\n", wrapper);
  if (wrapper == NULL) {
    exit(2);
  }

  for (int i = 5000; i < 100000; i++){
    for(int j = 0; j < i; j++){
      data[j] = 0;
      data2[j] = 0;
      data3[j] = 0;
      data4[j] = 0;
    }
    pi_ram_write(&ram, ram_ptr, (void *)data4, i);
    lennn[0] = i;
    printf("iteration: %d\n", i);
    pi_cluster_task(&cluster_task, cluster_entry, wrapper);
    //pi_cluster_task(&cluster_task_ram, cluster_entry_ram, wrapper);
    pi_cluster_send_task_to_cl(cluster_dev, &cluster_task);
    //pi_cluster_send_task_to_cl(cluster_dev, &cluster_task_ram);

    pi_ram_read(&ram, ram_ptr, (void *)data4, i);
  //   INIT_STATS();
  // ENTER_STATS_LOOP();
  // START_STATS();
    encrypt_serial(data2, i, key, iv);
    encrypt_serial_orig(data3, i, key, iv);
  
    // for(int j = 0; j < i; j++){
    //   if (data[j] !=data2[j] || data2[j] != data3[j] || data3[j] != data4[j]) {
    //     for (int o = 0; o < 10; o++){
    //       printf("wrong %d %d %d %d %d %d\n", i, j,  data[j+o], data2[j+o], data3[j+o], data4[j+o]);
    //     }
          
    //       exit(1);
    //   }
    // }
  }
  
  // STOP_STATS();
  // EXIT_STATS_LOOP();
  printf("encrypt serial\n", data[0], data[LEN-1]);
  chacha20_cluster_close(wrapper);
  
  // pi_cluster_task(&cluster_task, cluster_entry3, NULL);
//   // pi_cluster_send_task_to_cl(&cluster_dev, &cluster_task);
//    {INIT_STATS();

// // //   // executing the code multiple times to perform average statistics
//     ENTER_STATS_LOOP();
//     START_STATS();
    
//     STOP_STATS();
//     EXIT_STATS_LOOP();}


//     {INIT_STATS();

// // //   // executing the code multiple times to perform average statistics
//     ENTER_STATS_LOOP();
//     START_STATS();
//     encrypt_serial_orig(data3, LEN, key);
//     STOP_STATS();
//     EXIT_STATS_LOOP();}


  
  chacha20_cluster_close(wrapper);
  // closing the cluster
  pi_cluster_close(cluster_dev);
    


  return 0;
}