#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>


#include <linux/shm.h>
#include <linux/ipc.h>
#include <linux/stat.h>
#include <linux/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// Infiniband VAPI/EVAPI header files Mellanox MT23108 VAPI
#include <vapi.h>
#include <vapi_types.h>
#include <vapi_common.h>
#include <evapi.h>

// Remote HCA Info information
 typedef struct Remote_HCA_Info {
       unsigned long     opcode;
       unsigned long     length;
       IB_lid_t          dlid[256];
       VAPI_qp_num_t     rqp_num[256];
       VAPI_rkey_t       rkey;   // for remote RDAM request
       unsigned long     vaddr1; // virtual address fisrt 4 bytes
       unsigned long     vaddr2; // virtual address second 4 bytes
       u_int32_t         size;   // size of RDMA memory buffer
       char              dest_ip[256]; //destination server IP address 
 } Remote_HCA_Info;

#define SHARED_SEGMENT_SIZE  0x10000 // 16KB shared memory between U and K

// some internals opcodes for IB operations used in IBNAL
#define SEND_QP_INFO          0X00000001
#define RECV_QP_INFO          0X00000010
#define DEFAULT_SOCKET_PORT   11211 
#define LISTEN_QUEUE_SIZE     2048 
#define DEST_IP		      "10.128.105.26"

// server_thread
// + wait for an incoming connection from remote node 
// + receive remote HCA's data 
//
//
//
//
// 
void *server_thread(void *vargp)
{
  Remote_HCA_Info   *hca_data;
  Remote_HCA_Info   hca_data_buffer;
  
  int    serverfd;
  int    infd;
  struct hostent  *hp;
  struct sockaddr_in serveraddr;
  struct sockaddr_in clientaddr;
  int    sin_size=sizeof(struct sockaddr_in);
  int	 bytes_recv;
  int    i;


  hca_data = (Remote_HCA_Info *) vargp;
  
  if((serverfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("server_thread couldnot create a socket \n");
    pthread_exit((void *) 0);
  }
 
  printf("server_thread create a socket \n");

  bzero((char *) &serveraddr, sizeof(serveraddr));

  serveraddr.sin_family = AF_INET;
  serveraddr.sin_addr.s_addr = htons(INADDR_ANY);
  serveraddr.sin_port = htons((unsigned short) DEFAULT_SOCKET_PORT);
  
  if(bind(serverfd,(struct sockaddr *)&serveraddr,sizeof(struct sockaddr)) < 0) {
    printf("server_thread couldnot bind to a socket \n");
    pthread_exit((void *) 0);
  }

  printf("server_thread bind to a socket \n");

  if(listen(serverfd, LISTEN_QUEUE_SIZE) < 0) {
    printf("server_thread couldnot listen to a socket \n");
    pthread_exit((void *) 0);
  }

  printf("server_thread listen to a socket \n");

  //
  // I only expect to receive one HCA data from a remote HCA 
  //
  printf("server_thread: Waiting for a connection\n");
  infd= accept(serverfd,(struct sockaddr*)&clientaddr,&sin_size);
  printf("server_thread: Got an incoming connection");

  /* receive data from socket into buffer */
  bytes_recv = recv(infd,
                    &hca_data_buffer,  
                    sizeof(Remote_HCA_Info),
		    0);

  if(bytes_recv > 0) {
/*	  
      printf("server_thread receive data\n");
      printf("opcode is 0x%X\n", hca_data_buffer.opcode);
      printf("length is 0x%X\n", hca_data_buffer.length);

      for(i=0; i < 256; i++) {
        printf("dlid %d is 0x%X\n", i, hca_data_buffer.dlid[i]);
        printf("rqp_num %d is 0x%X\n", hca_data_buffer.rqp_num[i]);
      }

      printf("rkey is 0x%X\n", hca_data_buffer.rkey);
      printf("vaddr1 is 0x%X\n", hca_data_buffer.vaddr1);
      printf("vaddr2 is 0x%X\n", hca_data_buffer.vaddr2);
      printf("size is 0x%X\n", hca_data_buffer.size);
      printf("After conversion hton \n");
      printf("opcode is 0x%X\n", htonl(hca_data_buffer.opcode));
      printf("length is 0x%X\n", htonl(hca_data_buffer.length));

      for(i=0; i < 256; i++) {
        printf("dlid %d is 0x%X\n", htons(hca_data_buffer.dlid[i]));
        printf("rqp_num %d is 0x%X\n", htonl(hca_data_buffer.rqp_num[i]));
      }

      printf("rkey is 0x%X\n", htonl(hca_data_buffer.rkey));
      printf("vaddr1 is 0x%X\n", htonl(hca_data_buffer.vaddr1));
      printf("vaddr2 is 0x%X\n", htonl(hca_data_buffer.vaddr2));
      printf("size is 0x%X\n", htonl(hca_data_buffer.size));
*/     

      hca_data->opcode  = ntohl(hca_data_buffer.opcode); // long 
      hca_data->length  = ntohl(hca_data_buffer.length); // long

      for(i=0; i < 256; i++) {
        hca_data->dlid[i]    = ntohs(hca_data_buffer.dlid[i]);   // u_int16
        hca_data->rqp_num[i] = ntohl(hca_data_buffer.rqp_num[i]);// u_int32
      }

      hca_data->rkey    = ntohl(hca_data_buffer.rkey);   // u_int32
      hca_data->vaddr1  = ntohl(hca_data_buffer.vaddr1); // first word u_int32
      hca_data->vaddr2  = ntohl(hca_data_buffer.vaddr2); // second word u_int32
      hca_data->size    = ntohl(hca_data_buffer.size);   // u_int32
    }
    else {
      printf("server_thread receive ERROR bytes_recv = %d\n", bytes_recv);
    }

    close(infd);
    close(serverfd);

  printf("server_thread EXIT \n");
      
  pthread_exit((void *) 0);

}

//
// client_thread 
// + connect to a remote server_thread
// + send local HCA's data to remote server_thread
//
void *client_thread(void *vargp)
{

  Remote_HCA_Info   *hca_data;
  Remote_HCA_Info   hca_data_buffer;

  int    clientfd;
  struct hostent  *hp;
  struct sockaddr_in clientaddr;
  int    bytes_send;
  int    i;
  
  hca_data = (Remote_HCA_Info *) vargp;

  if((clientfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("client_thread couldnot create a socket \n");
    pthread_exit((void *) 0);
  }
 
  printf("client_thread create a socket \n");
  
  bzero((char *) &clientaddr, sizeof(clientaddr));

  clientaddr.sin_family = AF_INET;
  clientaddr.sin_addr.s_addr = inet_addr(hca_data->dest_ip);
  printf("client_thread get server Ip address = %s\n", hca_data->dest_ip);
  clientaddr.sin_port = htons((unsigned short) DEFAULT_SOCKET_PORT);
  memset(&(clientaddr.sin_zero), '\0', 8);

  connect(clientfd, (struct sockaddr *) &clientaddr, sizeof(struct sockaddr));

  printf("client_thread connect to  server Ip address = %s\n", hca_data->dest_ip);

  hca_data_buffer.opcode  = htonl(hca_data->opcode); // long 
  hca_data_buffer.length  = htonl(hca_data->length); // long

  for(i=0; i < 256; i++) {
    hca_data_buffer.dlid[i]    = htons(hca_data->dlid[i]);   // u_int16
    hca_data_buffer.rqp_num[i] = htonl(hca_data->rqp_num[i]);// u_int32
  }

  hca_data_buffer.rkey    = htonl(hca_data->rkey);   // u_int32
  hca_data_buffer.vaddr1  = htonl(hca_data->vaddr1); // first word u_int32
  hca_data_buffer.vaddr2  = htonl(hca_data->vaddr2); // second word u_int32
  hca_data_buffer.size    = htonl(hca_data->size);   // u_int32
 
  bytes_send = send(clientfd, & hca_data_buffer, sizeof(Remote_HCA_Info), 0); 
  
  if(bytes_send == sizeof(Remote_HCA_Info)) {
    printf("client_thread: send successfully \n");
  }
  else {
    printf("client_thread: send failed \n");
  }

  printf("client_thread EXIT \n");

  pthread_exit((void *) 0);
}


//
//  main 
//  + create a shared-memory between this main()/user address and
//    a kernel thread/kernel address space associated with inbal 
//    kernel module 
//  + access local HCA's data through this shared memory 
//
//  + create a server_thread for receiving remote HCA's data
//  + create a client_thread for sending out local HCA's data
//  + after receiving remote HCA's data update this shared memory
//
int  main(int argc , char *argv[])
{
  int              segment_id;
  struct shmid_ds  shmbuffer;
  int              segment_size;
  const int        shared_segment_size = sizeof(Remote_HCA_Info);
  key_t            key = 999;
  unsigned long    raddr;
  Remote_HCA_Info  *shared_memory;
  Remote_HCA_Info  exchange_hca_data;
  Remote_HCA_Info  remote_hca_data;
  int i; 

  /* pthread */
  pthread_t          sid;
  pthread_t          cid;
  pthread_attr_t     attr; 
  int                rc, status;

  char dest_ip[256];

  if(argc != 2) {
	  printf("USAGE:   uagent   server_ip_address\n");
	  printf("argc = %d \n", argc);
	  exit(1);
  }

  strcpy(&exchange_hca_data.dest_ip[0], argv[1]);
  printf("the destinational server IP address = %s\n", 
		                       &exchange_hca_data.dest_ip); 

  segment_id =  shmget(key, shared_segment_size, IPC_CREAT | 0666);

  printf("sys_shmget is done segment_id = %d\n", segment_id);

  shared_memory = (Remote_HCA_Info *) shmat(segment_id, 0, 0);

  if(shared_memory == (char *) -1) {
    printf("Shared memory attach failed shared_memory=%p\n",shared_memory);
    exit(0);
  }

  printf("shared menory attached at address %p\n", shared_memory);

  while (1) {
    if(shared_memory->opcode ==  SEND_QP_INFO) {
      printf("Local HCA data received from kernel thread\n");
      break;
    }
    usleep(1000);
    continue;
  }

  printf("Local HCA data received from kernel thread\n");

  // save local HCA's data in exchange_hca_data
  //
  exchange_hca_data.opcode  = shared_memory->opcode;
  exchange_hca_data.length  = shared_memory->length;

  for(i=0; i < 256; i++) {
    exchange_hca_data.dlid[i]    = shared_memory->dlid[i];
    exchange_hca_data.rqp_num[i] = shared_memory->rqp_num[i];
  }

  exchange_hca_data.rkey    = shared_memory->rkey;
  exchange_hca_data.vaddr1  = shared_memory->vaddr1;
  exchange_hca_data.vaddr2  = shared_memory->vaddr2;
  exchange_hca_data.size    = shared_memory->size;

  /* Initialize and set thread detached attribute */
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

  /* create a server thread for procsssing incoming remote node socket data */
  // 
  pthread_create(&sid, 
		  &attr, 
		  server_thread,
		  (Remote_HCA_Info *) &remote_hca_data);

  printf("Main: created a server thread \n");

  sleep(10);
  
  /* create a clint thread to send out local HCA data to remote node */
  pthread_create(&cid, 
		  &attr, 
		  client_thread,
		  (Remote_HCA_Info *) &exchange_hca_data);

  printf("Main: created a client  thread \n");

  /* synchronization between server_thread and client_thread */
  pthread_attr_destroy(&attr);

  rc = pthread_join(sid, (void **) &status);
  if(rc) {
    printf("Error: return code from pthread_join() is %d\n", rc);
    exit(-1);
  }

  printf("completed join with thread %d status = %d\n", sid, status);

  rc = pthread_join(cid, (void **) &status);
  if(rc) {
    printf("Error: return code from pthread_join() is %d\n", rc);
    exit(-1);
  }
  printf("completed join with thread %d status = %d\n", cid, status);

  // update shared memory with remote HCA's data 

  shared_memory->opcode = RECV_QP_INFO;
  shared_memory->length = remote_hca_data.length;
  for(i=0; i < 256; i++) {
    shared_memory->dlid[i]   = remote_hca_data.dlid[i];
    shared_memory->rqp_num[i]= remote_hca_data.rqp_num[i];
  }
  shared_memory->rkey   = remote_hca_data.rkey;
  shared_memory->vaddr1 = remote_hca_data.vaddr1;
  shared_memory->vaddr2 = remote_hca_data.vaddr2;
  shared_memory->size   = remote_hca_data.size;

  sleep(5);

  shared_memory->opcode = RECV_QP_INFO;
  shared_memory->length = remote_hca_data.length;
  for(i=0; i < 256; i++) {
    shared_memory->dlid[i]   = remote_hca_data.dlid[i];
    shared_memory->rqp_num[i]= remote_hca_data.rqp_num[i];
  }
  
  shared_memory->rkey   = remote_hca_data.rkey;
  shared_memory->vaddr1 = remote_hca_data.vaddr1;
  shared_memory->vaddr2 = remote_hca_data.vaddr2;
  shared_memory->size   = remote_hca_data.size;

  sleep(10);
  
//  shmdt(shared_memory);
   
  printf("uagent is DONE \n");
  
 

  exit(0);

}

