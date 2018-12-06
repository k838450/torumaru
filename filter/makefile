#Makefile for testfilter.c

cfilter: filter.o collect_proc_info.o
	gcc -g -o filter filter.o collect_proc_info.o -lnetfilter_queue

filter: filter.c
	gcc -c filter.c

collect_proc_info: collect_proc_info.c
	gcc -c collect_proc_info.c
