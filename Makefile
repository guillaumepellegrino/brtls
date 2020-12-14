CFLAGS+=-MD -Wall -Wextra -Werror -Wno-error=deprecated-declarations
LDFLAGS+=-lssl -lcrypto
BUILD?=build
INSTALL?=install
TARGET=$(BUILD)/brtls
OBJECTS=$(addprefix $(BUILD)/,brtls.o tls.o)

all: $(TARGET)

-include $(OBJECTS:.o=.d)

$(TARGET): $(OBJECTS)
	$(CC) -o $(@) $(^) $(LDFLAGS)

$(BUILD)/%.o: %.c | $(BUILD)
	$(CC) -o $(@) -c $(<) $(CFLAGS)

$(BUILD):
	mkdir -p $(BUILD)

install:
	$(INSTALL) -m 4755 $(TARGET) /usr/bin/

clean:
	rm -rf $(BUILD)

cert:
	# Generate a 4096 bits Private Key using RSA
	openssl genrsa -out key.pem 4096

	# Generate a Certificate Signing Request
	openssl req -new -key key.pem -out brtls.csr

	# Self sign the CSR
	openssl x509 -req -days 365 -in brtls.csr -signkey key.pem -out cert.pem


.PHONY: all install clean cert

