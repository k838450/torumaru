# torumaruくん

## auditの設定
auditctl -a always,exit -F arch=b64 -S execve,openを記述
固定する場合は/etc/audit/rules.d/audit.rulesに記述

## iptablesの設定
iptables -A OUTPUT -j NFQUEUE --queue-num 2
