# Tarea 3 – Taller de Redes  
**Intercepción y modificación de tráfico PostgreSQL con Scapy + Docker**

## 🧱 Estructura general

Se crearon tres contenedores Docker:

| Contenedor       | Rol                   | Descripción                                     |
|------------------|------------------------|-------------------------------------------------|
| `postgres_server`| Servidor PostgreSQL     | Base de datos escuchando en el puerto 5432     |
| `postgres_client`| Cliente de PostgreSQL   | Ejecuta consultas con `psql`                   |
| `scapy_sniffer`  | Sniffer y manipulador   | Escucha, intercepta y modifica paquetes TCP    |

Todos los contenedores están conectados a una red Docker bridge personalizada llamada `sniffer_net`.

---

## ⚙️ Docker Compose

```bash
docker network create --driver=bridge --subnet=192.168.100.0/24 sniffer_net
docker compose up --build -d

🐍 Scripts disponibles en ./scripts (montados en el contenedor Scapy)
✅ 1. sniffer.py

Muestra todo el tráfico TCP hacia PostgreSQL (puerto 5432)

from scapy.all import *

def callback(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        print("📦", pkt.summary())
        print(pkt[Raw].load)

sniff(iface="eth0", filter="tcp port 5432", prn=callback, store=0)

📌 Ejecutar desde scapy_sniffer:

docker exec -it scapy_sniffer python /scripts/sniffer.py

⚠️ Activar iptables en cliente para pruebas de modificación

Dentro del contenedor postgres_client:

docker exec -u root -it postgres_client sh
iptables -A OUTPUT -p tcp --dport 5432 -j DROP

✅ Esto evita que el paquete original llegue al servidor.
💥 2. modify_query_break_it.py

Intercepta consultas y reemplaza el payload por algo inválido:

from scapy.all import *

def intercept(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if pkt[TCP].dport == 5432:
            corrupto = b'\x00\xff\xff\xff' + pkt[Raw].load[4:]
            pkt[TCP].remove_payload()
            pkt = pkt / Raw(load=corrupto)
            del pkt[IP].chksum
            del pkt[TCP].chksum

            mac = getmacbyip(pkt[IP].dst)
            if mac:
                ether = Ether(dst=mac)
                sendp(ether/pkt[IP], iface="eth0", verbose=False)
                print("💣 Consulta corrupta enviada.")
            else:
                print("⚠️ MAC no encontrada.")

sniff(iface="eth0", filter="tcp port 5432", prn=intercept, store=0)

📌 Resultado esperado: el servidor rechaza la consulta con error.
🎲 3. fuzzing.py

Envía tráfico basura con el formato de paquete PostgreSQL

from scapy.all import *

pkt = IP(dst="postgres_server") / TCP(sport=RandShort(), dport=5432, flags="PA") / Raw(load=b'\x00\xff\xff\xff')
send(pkt, iface="eth0")
print("Fuzzing packet enviado.")

📌 Ejecutar desde Scapy:

docker exec -it scapy_sniffer python /scripts/fuzzing.py

📌 Ver errores o cierres en el log de postgres_server:

docker logs postgres_server

🧪 Pruebas dentro del cliente
Consulta válida

docker exec -it postgres_client psql -h postgres_server -U postgres -c "SELECT 'ok';"

Resultado esperado con sniffer activo y iptables ON

    No se recibe respuesta

    En scapy_sniffer, se imprime el paquete

    El modificado es el único que llega

🧼 Para desactivar iptables

docker exec -u root -it postgres_client sh
iptables -D OUTPUT -p tcp --dport 5432 -j DROP

✅ ¿Cómo demostrar la funcionalidad?

    Mostrar psql colgado sin respuesta

    Mostrar Scapy capturando y modificando el paquete

    Mostrar que el servidor rechaza la consulta (FATAL: invalid frontend message type)

    Explicar el flujo con red docker bridge compartida

📦 Archivos importantes

    docker-compose.yml: define los 3 contenedores en red sniffer_net

    scripts/sniffer.py: captura tráfico TCP

    scripts/modify_query_break_it.py: modifica la consulta

    scripts/fuzzing.py: prueba inyecciones de paquetes inválidos

🚀 Bonus: toggle rápido de firewall

Dentro de postgres_client, podés usar un script:

# toggle_firewall.sh
#!/bin/sh

if [ "$1" = "on" ]; then
  iptables -A OUTPUT -p tcp --dport 5432 -j DROP
  echo "🔒 iptables activado"
elif [ "$1" = "off" ]; then
  iptables -D OUTPUT -p tcp --dport 5432 -j DROP
  echo "🔓 iptables desactivado"
else
  echo "Uso: ./toggle_firewall.sh [on|off]"
fi

📚 Conclusión

Este entorno Docker permite estudiar e intervenir el tráfico TCP de una base de datos PostgreSQL usando Scapy. Se demostró:

    Intercepción de paquetes reales

    Modificación efectiva de consultas antes de que lleguen al servidor

    Inyecciones directas por fuzzing

    Bloqueo del paquete original usando iptables

    ✅ Todo sin romper la arquitectura de red de Docker ni el cliente/servidor.


---

¿Querés que también lo convierta a PDF o que lo formatee para entregar como informe
