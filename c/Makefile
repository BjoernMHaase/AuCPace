SOURCE = tweetnacl.c main.c AuCPace25519.c \
      ../scrypt-1.3.0/lib/crypto/crypto_scrypt-ref.c \
      ../scrypt-1.3.0/libcperciva/alg/sha256.c \
      ../scrypt-1.3.0/libcperciva/util/insecure_memzero.c

LIBS = 
INCLUDE = -I../scrypt-1.3.0/lib -I../scrypt-1.3.0/libcperciva/alg \
          -I../scrypt-1.3.0/libcperciva/util \
          -I../scrypt-1.3.0/libcperciva/cpusupport

main: $(SOURCE)
	gcc -o main.out $(SOURCE) $(LIBS) $(INCLUDE)

run: main
	./main.out

clean:
	rm main.out
