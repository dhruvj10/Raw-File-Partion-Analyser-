CXX = clang++
TARGET = boot_info
SOURCE = boot_info.cpp
CXXFLAGS = -std=c++11 -Wall -Wextra
LDFLAGS = -lssl -lcrypto

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) $(SOURCE) -o $(TARGET) $(LDFLAGS)
	chmod +x $(TARGET)

clean:
	rm -f $(TARGET)