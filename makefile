RM := rm -rf
LIBS := -lssl -lcrypto
USER_OBJS := 
OPTN := -DOPENSSL

C_SRCS += \
./src/net.c 

OBJS += \
./src/net.o 

C_DEPS += \
./src/net.d 

src/%.o: ./src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc $(OPTN) -Wall -c -fmessage-length=0 -fPIC -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

all: libLibMiniNet.so

libLibMiniNet.so: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: Cross GCC Linker'
	gcc -shared -o "libLibMiniNet.so" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

clean:
	-$(RM) $(OBJS)$(C_DEPS)$(LIBRARIES) libLibMiniNet.so
	-@echo ' '