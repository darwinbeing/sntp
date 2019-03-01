
default:
	gcc -o sntp sntp.c -lpthread -ldl

clean:
	@rm -rf sntp
