#!/bin/sh

inode_num=`cat /proc/net/tcp | grep -i :$1 | awk '{print $10}'`
pid=()

for i in  $inode_num
do
	#pid+=(`ls -l /proc/[1-9]*/fd/[1-9]* 2>/dev/null | grep $i | awk '{print $9}'|sed "s/\/proc\//\/proc /g" | tr "/" "\n" | grep proc | awk '{print $2}' | tr "\n" "," `)
	
	pid+=(`ls -l /proc/[1-9]*/fd/[1-9]* 2>/dev/null | grep $i | awk '{print $9}' | sed -e "s/\/proc\///" | sed -e "s/\/fd\/[0-9]\+//" | tr "\n" "," `)
done

echo -e ${pid[@]} > pid.txt 
#echo -e ${pid[@]}  
exit 0
