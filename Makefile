CC=g++
CFLAGS=-c -Wall
LDFLAGS=-I/usr/local/Cellar/cryptopp/5.6.2/include -L/usr/local/Cellar/cryptopp/5.6.2/lib -lcryptopp
SOURCES=src/rncryptor.cpp src/rndecryptor.cpp src/rnencryptor.cpp src/main.cpp src/tests.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=rncryptor

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJECTS) $(EXECUTABLE)
