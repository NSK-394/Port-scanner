import socket

def port_scanning(target,ports):
    print(f"Scanning {target} in process.... \n")
    for port in ports:
        try :
            sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target,port))
            if result ==0:
                print(f"[open] Port {port}")
            sock.close()
        except Exception as e:
            print(f"Error Scanning Port{port}:{e}")
            
            
if __name__=="__main__":
    target=input("Enter the target ip or domain: ")
    
    ports_to_scan=[21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]
    port_scanning(target,ports_to_scan)
    