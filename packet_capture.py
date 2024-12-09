import socket
import os
from threading import Thread

# 패킷 처리 함수
def packet_callback(sock):
    while True:
        packet, addr = sock.recvfrom(65535)  # 최대 65535 바이트 수신
        src_ip = addr[0]
        dst_ip = addr[1]
        packet_length = len(packet)
        
        # TCP 패킷인지 확인
        if packet[9] == 6:  # IP 프로토콜 6은 TCP
            src_port = (packet[20] << 8) + packet[21]
            dst_port = (packet[22] << 8) + packet[23]
            protocol = "TCP"
        # UDP 패킷인지 확인
        elif packet[9] == 17:  # IP 프로토콜 17은 UDP
            src_port = (packet[20] << 8) + packet[21]
            dst_port = (packet[22] << 8) + packet[23]
            protocol = "UDP"
        else:
            continue  # TCP 또는 UDP가 아닌 패킷은 무시

        payload = packet[24:]  # 실제 데이터 (헤더 이후)
        payload_hex = payload.hex(' ')

        # 출력 형식
        log_entry = (
            f"{protocol} Packet\n"
            f"   Source IP: {src_ip}\n"
            f"   Destination IP: {dst_ip}\n"
            f"   Source Port: {src_port}\n"
            f"   Destination Port: {dst_port}\n"
            f"   Packet Length: {packet_length} bytes\n"
            f"   Payload ({len(payload)} bytes):\n"
            f"{payload_hex}\n"
        )

        # 콘솔 출력
        print(log_entry)
        
        # 파일에 저장
        with open("packet_log.txt", "a") as log_file:
            log_file.write(log_entry)

# 패킷 캡쳐 함수
def capture_packets(interface):
    # 소켓 생성
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface, 0))
    print(f"{interface}에서 패킷 캡쳐 시작")
    packet_callback(sock)

if __name__ == "__main__":
    # 사용 가능한 인터페이스 출력
    os.system("ifconfig")

    interface = input("캡쳐할 네트워크 인터페이스를 입력하세요 (예: eth0): ")

    # 패킷 캡쳐 실행
    capture_packets(interface)
