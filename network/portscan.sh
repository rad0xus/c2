cat /proc/net/tcp | awk 'NR>1 && $4=="0A" {
  split($2,a,":");
  ip=sprintf("%d.%d.%d.%d", strtonum("0x"substr(a[1],7,2)), strtonum("0x"substr(a[1],5,2)), strtonum("0x"substr(a[1],3,2)), strtonum("0x"substr(a[1],1,2)));
  port=strtonum("0x"a[2]);
  print ip":"port
}'
