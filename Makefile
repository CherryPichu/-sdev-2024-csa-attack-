LDLIBS += -lpcap

All : main.c
	gcc -o csa-attack main.c -lpcap
