import socket

def start_server():
    # The correct 11-hex code from the Agadir hash
    SECRET_CODE = "a25fd3c8373"
    FLAG = "INFODAYS{4G4D1R_ST3G4N0GR4PHY_M4ST3R_2030}"

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind to all interfaces on port 1234
    server_socket.bind(('0.0.0.0', 1234))
    server_socket.listen(5)
    
    print("Server is listening on port 1234...")

    while True:
        client_socket, addr = server_socket.accept()
        client_socket.send(b"--- Agadir Stadium Access Control ---\n")
        client_socket.send(b"Enter the 11-hex Architect Signature: ")
        
        # Receive the input and clean it
        data = client_socket.recv(1024).decode().strip()
        
        if data == SECRET_CODE:
            client_socket.send(f"\n[+] Access Granted! Here is your flag: {FLAG}\n".encode())
        else:
            client_socket.send(b"\n[!] Access Denied. Wrong signature.\n")
        
        client_socket.close()

if __name__ == "__main__":
    start_server()
