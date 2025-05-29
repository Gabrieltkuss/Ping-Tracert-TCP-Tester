import socket
import time
import struct
import select
import customtkinter as vk
from tkinter import *
import threading
from queue import Queue
from scapy.all import IP, TCP, ICMP, sr1


def tcp_ping():
    host = ipEntry.get()
    port = int(portEntry.get())

    logBox.delete(1.0, END)

    global stop_test
    stop_test = False

    # Variáveis para armazenar métricas
    pings = []
    packet_loss_count = 0
    packet_sent_count = 0

    # Fila para atualizar a interface gráfica
    log_queue = Queue()

    def update_log():
        while not log_queue.empty():
            message = log_queue.get()
            logBox.insert(END, message)
            logBox.see(END)

        if not stop_test:
            logBox.after(100, update_log)  # Verifica a fila novamente após 100ms

    def send_pings():
        nonlocal packet_sent_count, packet_loss_count

        while not stop_test:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)

                start_time = time.time()
                s.connect((host, port))
                end_time = time.time()

                rtt = (end_time - start_time) * 1000
                pings.append(rtt)

                message = f"Pacote SYN enviado para {host}:{port}.\n Tempo de retorno: {rtt:.6f} ms.\n"
                log_queue.put(message)

            except Exception as e:
                packet_loss_count += 1
                message = f"Erro ao enviar pacote SYN para {host}:{port}: {e}\n"
                log_queue.put(message)
            finally:
                packet_sent_count += 1
                s.close()

            time.sleep(1)

    global ping_thread
    ping_thread = threading.Thread(target=send_pings)
    ping_thread.start()

    logBox.after(100, update_log)  # Inicia a verificação da fila

    def calculate_metrics():
        nonlocal packet_sent_count, packet_loss_count

        if packet_sent_count > 0:
            packet_loss_percent = (packet_loss_count / packet_sent_count) * 100
        else:
            packet_loss_percent = 0

        if pings:
            min_ping = min(pings)
            max_ping = max(pings)
            avg_ping = sum(pings) / len(pings)
        else:
            min_ping = max_ping = avg_ping = 0

        metrics = f"""
        Resultados:
        -------------
        Pacotes Enviados: {packet_sent_count}
        Pacotes Perdidos: {packet_loss_count}
        Porcentagem de Perda de Pacotes: {packet_loss_percent:.2f}%
        Ping Mínimo: {min_ping:.2f} ms
        Ping Médio: {avg_ping:.2f} ms
        Ping Máximo: {max_ping:.2f} ms
        """
        log_queue.put(metrics)

    def stop_and_calculate():
        global stop_test
        stop_test = True
        ping_thread.join()
        calculate_thread = threading.Thread(target=calculate_metrics)
        calculate_thread.start()

    stopButton.configure(command=stop_and_calculate)

def stop_test():
    global stop_test
    stop_test = True
    ping_thread.join()

def clear_logs():
    logBox.delete(1.0, END)

def on_enter(event):
    tcp_ping_threaded()

def tcp_ping_threaded():
    threading.Thread(target=tcp_ping).start()

def clearButton_threaded():
    threading.Thread(target=clear_logs).start()

stop_test_traceroute = False

def tcp_traceroute():
    global stop_test_traceroute
    host = TraceipEntry.get()
    port = int(TraceportEntry.get())

    TracelogBox.delete(1.0, END)

    stop_test_traceroute = False

    log_queue = Queue()

    def update_log():
        while not log_queue.empty():
            msg = log_queue.get()
            TracelogBox.insert(END, msg)
            TracelogBox.see(END)
        if not stop_test_traceroute:
            TracelogBox.after(100, update_log)

    def traceroute_proc():
        try:
            ip = socket.gethostbyname(host)
            log_queue.put(f"Scan report for {host} ({ip})\n")
            rdns = None
            try:
                rdns = socket.gethostbyaddr(ip)[0]
            except:
                pass
            if rdns:
                log_queue.put(f"rDNS record for {ip}: {rdns}\n")

            open_port, latency = is_port_open(ip, port)
            port_status = "open" if open_port else "closed"
            log_queue.put(f"\nPORT   STATE SERVICE\n{port}/tcp {port_status}  http\n")
            log_queue.put("TRACEROUTE (using port {}/tcp)\n".format(port))
            log_queue.put("HOP RTT      ADDRESS\n")

            max_hops = 30
            timeout = 2

            for ttl in range(1, max_hops + 1):
                if stop_test_traceroute:
                    log_queue.put("Teste interrompido pelo usuário.\n")
                    break

                pkt = IP(dst=ip, ttl=ttl) / TCP(dport=port, flags='S')
                start_time = time.time()
                reply = sr1(pkt, verbose=0, timeout=timeout)
                rtt = (time.time() - start_time) * 1000 if reply else None

                if reply is None:
                    log_queue.put(f"{ttl:<3} Request timed out No response\n")
                else:
                    addr = reply.src
                    rtt_str = f"{rtt:.2f} ms" if rtt else "No RTT"
                    log_queue.put(f"{ttl:<3} {rtt_str:<9} {addr}\n")

                    # Se recebeu SYN/ACK ou RST, termina o traceroute
                    if reply.haslayer(TCP):
                        flags = reply[TCP].flags
                        if flags & 0x12 or flags & 0x14:
                            log_queue.put("Destino alcançado.\n")
                            break
            else:
                log_queue.put("Número máximo de saltos atingido.\n")

        except Exception as e:
            log_queue.put(f"Erro: {e}\n")

    threading.Thread(target=traceroute_proc, daemon=True).start()
    update_log()

def tcp_traceroute_threaded():
    threading.Thread(target=tcp_traceroute, daemon=True).start()

def clear_trace_logs():
    TracelogBox.delete(1.0, END)

def clear_trace_threaded():
    threading.Thread(target=clear_trace_logs).start()

def stop_test_traceroute_func():
    global stop_test_traceroute
    stop_test_traceroute = True

def on_enterT(event):
    tcp_traceroute_threaded()

# Sua função is_port_open permanece igual
def is_port_open(host, port=80, timeout=1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        start = time.time()
        s.connect((host, port))
        latency = (time.time() - start) * 1000  # ms
        s.close()
        return True, latency
    except Exception:
        return False, None

ipp = vk.CTk()
ipp.title("Pinger TCP Tester")
vk.set_appearance_mode("dark")
vk.set_default_color_theme("dark-blue")
ipp.geometry("550x350")
ipp.resizable(False, False)
ipp.attributes("-alpha", 0.9)

ipp.tabview = vk.CTkTabview(ipp, width=550,height=350)
ipp.tabview.place(x=0,y=0)

ipp.grid_rowconfigure(0, weight=1)
ipp.grid_columnconfigure(0, weight=1)

ipp.tabview.add("PING")
ipp.tabview.add("TRACERT")

ipLabel = vk.CTkLabel((ipp.tabview.tab("PING")), text="IP:", font=("Century Gothic", 20), fg_color="transparent")
ipLabel.place(x=95, y=5)

ipEntry = vk.CTkEntry((ipp.tabview.tab("PING")), width=200, fg_color="black")
ipEntry.place(x=120, y=10)

portLabel = vk.CTkLabel((ipp.tabview.tab("PING")), text="Porta:", font=("Century Gothic", 20), fg_color="transparent")
portLabel.place(x=61, y=35)

portEntry = vk.CTkEntry((ipp.tabview.tab("PING")), width=100, fg_color="black")
portEntry.place(x=120, y=40)
portEntry.bind("<Return>", on_enter)

testButton = vk.CTkButton((ipp.tabview.tab("PING")), text="Iniciar Teste", width=100, fg_color="#002663", command=lambda: tcp_ping_threaded())
testButton.place(x=15, y=75)

stopButton = vk.CTkButton((ipp.tabview.tab("PING")), text="Parar Teste", width=100, fg_color="#8b0000", command=lambda: stop_test)
stopButton.place(x=15, y=105)

clearButton = vk.CTkButton((ipp.tabview.tab("PING")), text="Limpar Logs", width=100, fg_color="#8b0000", command=lambda: clearButton_threaded())
clearButton.place(x=15, y=135)

logBox = vk.CTkTextbox((ipp.tabview.tab("PING")), height=220, width=410, wrap="word")
logBox.place(x=120, y=75)

# TRACERT -----------------#

TraceipLabel = vk.CTkLabel((ipp.tabview.tab("TRACERT")), text="IP:", font=("Century Gothic", 20), fg_color="transparent")
TraceipLabel.place(x=95, y=5)

TraceipEntry = vk.CTkEntry((ipp.tabview.tab("TRACERT")), width=200, fg_color="black")
TraceipEntry.place(x=120, y=10)

TraceportLabel = vk.CTkLabel((ipp.tabview.tab("TRACERT")), text="Porta:", font=("Century Gothic", 20), fg_color="transparent")
TraceportLabel.place(x=61, y=35)

TraceportEntry = vk.CTkEntry((ipp.tabview.tab("TRACERT")), width=100, fg_color="black")
TraceportEntry.place(x=120, y=40)
TraceportEntry.bind("<Return>", on_enterT)

TracetestButton = vk.CTkButton((ipp.tabview.tab("TRACERT")), text="Iniciar Teste", width=100, fg_color="#002663", command=lambda: tcp_traceroute_threaded())
TracetestButton.place(x=15, y=75)

TracestopButton = vk.CTkButton((ipp.tabview.tab("TRACERT")), text="Parar Teste", width=100, fg_color="#8b0000", command=stop_test_traceroute_func)
TracestopButton.place(x=15, y=105)

TraceclearButton = vk.CTkButton((ipp.tabview.tab("TRACERT")), text="Limpar Logs", width=100, fg_color="#8b0000", command=clear_trace_threaded)
TraceclearButton.place(x=15, y=135)

TracelogBox = vk.CTkTextbox((ipp.tabview.tab("TRACERT")), height=220, width=410, wrap="word")
TracelogBox.place(x=120, y=75)


#----------------------------------------------------------------#

CreditosLabel = vk.CTkLabel(ipp, text="Desenvolvido por Gabriel Kuss", font=("Century Gothic", 10), fg_color="transparent")
CreditosLabel.place(x=380, y=0)



ipp.mainloop()
