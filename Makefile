# Defining which compiler to use
CXX = g++

# CXXFLAGS sets the options for compiling C++ code
# Here, -std=c++17 tells the compiler to use the C++17 standard
CXXFLAGS = -std=c++17 -O2

# LDFLAGS are the libraries needed for this project
LDFLAGS = -lntl -lgmp -lssl -lcrypto
SRCS = main.cpp params.cpp shamir.cpp threshold.cpp lagrange.cpp crypto.cpp

OBJS = $(SRCS:.cpp=.o)

# Default target
TARGET = threshold_elgamal

all: $(TARGET)

# Linking all object files into final executable which is threshold_elgamal
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# Compiling .cpp files into .o files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

#Removing previously compiled files to compile new ones
clean:
	rm -f $(OBJS) $(TARGET)
