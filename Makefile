all:	SecureChat

SecureChat: SecureChat.o
	gcc SecureChat.o -lcrypto -o SecureChat
SecureChat.o: SecureChat.c
	gcc SecureChat.c -c
clean:
	rm -rf *.o SecureChat
