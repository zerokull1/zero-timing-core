# ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
all: shield_iat.spv vk_iat_bridge

shield_iat.spv: shield_iat.comp
	glslc shield_iat.comp -o shield_iat.spv

vk_iat_bridge: vk_iat_bridge.c shield_iat.spv
	gcc -O3 vk_iat_bridge.c -lvulkan -o vk_iat_bridge

run: all
	./vk_iat_bridge

clean:
	rm -f shield_iat.spv vk_iat_bridge
