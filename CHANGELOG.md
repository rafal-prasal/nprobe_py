## Changelog
### 0.0.3
* adding -T parameter with @NTOPNG@ template
* adding verbose dependent printing
* removing redunant code
  * Netflow/set == 2 and Netflow/set == 3 are sharing record scan
* NetFlow IPFIX
  * adding expected sequence number, need to wait for set=2 or 3 to properly handle it
  * one NetFlow message means now one zmq message
  * fixed performance timers in case of multiple sets within NetFlow message
* general performance fixes
### 0.0.2
* protocols support
  * NetfFow/set == 3 
	  * support for scopes
  * ntop/zmq with v1 header
	  * source_id - to identifiy nprobe_py within ntop
	  * msg_id - to monitor dropping of ntop/zmq messages
* parameter:
  * --zmq-source-id (default = 1)
### 0.0.1 (2023.04.06)
* initial release
