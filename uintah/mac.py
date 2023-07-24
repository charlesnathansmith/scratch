import uuid

#Retrieve local MAC address
mac_ascii = hex(uuid.getnode())[2:]
mac = bytearray.fromhex(mac_ascii)

for i in range(6):
    mac[i] = (((mac[i] & 0xf0) >> 4) ^ 9) + (((mac[i] & 0xf) ^ 9) << 4)

print("Binary value to store in MAC key")
print(mac)
