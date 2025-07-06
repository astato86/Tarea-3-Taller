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
