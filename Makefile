all : sendarp

sendarp: main.o
	g++ -g -o sendarp main.o -lpcap -lnet

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f sendarp
	rm -f *.o

