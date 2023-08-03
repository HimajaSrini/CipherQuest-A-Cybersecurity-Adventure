# CipherQuest-A-Cybersecurity-Adventure
# AES Encryption and Decryption
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_message(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, get_random_bytes(16))
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def decrypt_message(key, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, get_random_bytes(16))
    plaintext = cipher.decrypt(ciphertext)
    return plaintext
# Network Packet Analysis
from scapy.all import sniff

def packet_handler(packet):
    if packet.haslayer("TCP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        src_port = packet["TCP"].sport
        dst_port = packet["TCP"].dport

        print(f"Packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}")

# Sniffing packets on the network interface
sniff(filter="tcp", prn=packet_handler, count=10)
