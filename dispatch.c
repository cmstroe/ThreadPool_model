#include "dispatch.h"
#include "analysis.h"
#include <pthread.h>
#include <pcap.h>
#include <stdio.h>
#include "sniff.h"
#include <pcap.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

//the maximum of threads
#define THREAD 10
int first=0;
struct node
{
    //the queue that will contain all packets
    //it has to be initialised
    struct pcap_pkthdr *head;
    struct node *next;
    unsigned char *packet;
    int state;
};
struct node *head=NULL;
struct node*tail=NULL;
unsigned long size=0;
pthread_t thread[THREAD];
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond= PTHREAD_COND_INITIALIZER;

void enque (struct node * n)
{
    //lock threads to process the next packet in the queue
    pthread_mutex_lock(&lock);
    if(head==NULL)
        head=tail=n;
    else
    {
        //if queue still non empty, move on to the next element
        tail->next=n;
        tail=n;
    }
    size++;
    //dequeue one packet by unblocking thread
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&lock);
}

void *dequeue(void *args)
{
    while(first)
    {
        pthread_mutex_lock(&lock);
        while(size < 1)
        {
            pthread_cond_wait(&cond, &lock);
        }
        if (first)
        {
            struct node* m;
            m=head;
            /*if the algorithm hasn't reached and end, store
            the current node in the beginning of the queue
            and then free it
            */
            struct node* current = (struct node *) malloc(sizeof(struct node));
            *current=*head;
        if( head== tail)
        {
            //move on to the next packet
            head=tail = NULL;
        }
        else
        {
            head=head->next;
        }
        size--;
        free(m);
        pthread_mutex_unlock(&lock);
        analyse(current->head,current->packet,current->state);
        free(current->head);
        free(current->packet);
        free(current);
    }else
    {
        //unlock mutex to stop the other threads
        pthread_mutex_unlock(&lock);
    }
    }
    return (void *) args;
}
void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {

  if(first==0)
  {
      first++;
      int i;
      for(i=0;i< THREAD; i++)
      {
          if(pthread_create(&thread[i],NULL,&dequeue, (void*) NULL))
          {
              printf("%d thread creation failure for thread: \n",i);
          }
      }
  }
  struct node* new= (struct node *) malloc(sizeof(struct node));
  new->head = (struct pcap_pkthdr *) malloc(sizeof(struct pcap_pkthdr));
  new->packet=(unsigned char*)calloc(new->head->len +2, sizeof(char));
  memcpy(new->packet,packet, new->head->len);
  new->state = verbose;
  new->next=NULL;
  //send copied packet from memcpy as a node
  enque(new);
 }

 void free_t()
 {   //rejoin the threads after freeing them
     pthread_mutex_lock(&lock);
     pthread_cond_destroy(&cond);
     int i;
     for(i=0;i< THREAD; i++)
     {
         pthread_join(thread[i],(void*) NULL);
     }
 }
