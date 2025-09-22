

# Configuracion Inicial PRIVADO_ID_CON_GOLANG:


# Actualizar sistema

log "Actualizando sistema..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git build-essential make gcc g++ pkg-config postgresql postgresql-contrib redis-server unzip bc

# Instalar Go
cd /tmp
wget -q https://golang.org/dl/go1.24.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.linux-amd64.tar.gz

# Configurar Go
cat >> ~/.bashrc << 'BASHRC'
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export GOBIN=$GOPATH/bin
export PATH=$PATH:$GOBIN
BASHRC

source ~/.bashrc
mkdir -p $HOME/go/{bin,src,pkg}

# Instalar Vault
log "Instalando HashiCorp Vault..."
wget -q https://releases.hashicorp.com/vault/1.15.2/vault_1.15.2_linux_amd64.zip
unzip -q vault_1.15.2_linux_amd64.zip
sudo mv vault /usr/local/bin/
rm vault_1.15.2_linux_amd64.zip

# Configurar PostgreSQL
log "Configurando PostgreSQL..."
sudo systemctl start postgresql
sudo systemctl enable postgresql

sudo -u postgres psql << 'EOPSQL'
DROP DATABASE IF EXISTS issuernode_db;
DROP USER IF EXISTS issuernode;
CREATE USER issuernode WITH PASSWORD 'issuernode_password';
ALTER USER issuernode CREATEDB;
CREATE DATABASE issuernode_db OWNER issuernode;
GRANT ALL PRIVILEGES ON DATABASE issuernode_db TO issuernode;
\q
EOPSQL

# Configurar autenticación PostgreSQL
PG_VERSION=$(sudo -u postgres psql -t -c "SELECT version();" | grep -oE '[0-9]+\.[0-9]+' | head -1)
PG_HBA_FILE="/etc/postgresql/$PG_VERSION/main/pg_hba.conf"

sudo cp "$PG_HBA_FILE" "$PG_HBA_FILE.backup"
sudo sed -i 's/local   all             all                                     peer/local   all             all                                     md5/' "$PG_HBA_FILE"
sudo sed -i 's/host    all             all             127.0.0.1\/32            ident/host    all             all             127.0.0.1\/32            md5/' "$PG_HBA_FILE"
sudo systemctl restart postgresql

# Configurar Redis
log "Configurando Redis..."
sudo systemctl start redis-server
sudo systemctl enable redis-server

# Crear directorios del proyecto
log "Creando directorios del proyecto..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Clonar proyecto
log "Clonando issuer-node..."
git clone https://github.com/0xPolygonID/issuer-node.git
cd issuer-node

# Configurar Vault
log "Configurando Vault..."
mkdir -p $HOME/vault-{data,config,plugins}

cat > $HOME/vault-config/vault.hcl << 'VAULTCONF'
storage "file" {
  path = "/home/$USER/vault-data"
}
listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = 1
}
ui = true
disable_mlock = true
plugin_directory = "/home/$USER/vault-plugins"
VAULTCONF

# Expandir variables en configuración de Vault
envsubst < $HOME/vault-config/vault.hcl > $HOME/vault-config/vault-expanded.hcl

# Iniciar Vault
log "Iniciando Vault..."
nohup vault server -config=$HOME/vault-config/vault-expanded.hcl > $HOME/vault-config/vault.log 2>&1 &
VAULT_PID=$!
echo $VAULT_PID > $HOME/vault-config/vault.pid

sleep 5

# Configurar Vault
export VAULT_ADDR='http://127.0.0.1:8200'
vault operator init -key-shares=1 -key-threshold=1 > $HOME/vault-config/vault-keys.txt

UNSEAL_KEY=$(grep "Unseal Key" $HOME/vault-config/vault-keys.txt | awk '{print $NF}')
ROOT_TOKEN=$(grep "Root Token" $HOME/vault-config/vault-keys.txt | awk '{print $NF}')

echo "$UNSEAL_KEY" > $HOME/vault-config/unseal-key
echo "$ROOT_TOKEN" > $HOME/vault-config/root-token
chmod 600 $HOME/vault-config/{unseal-key,root-token}

vault operator unseal "$UNSEAL_KEY"
vault login "$ROOT_TOKEN"
vault secrets enable -path=secret -version=2 kv

# Compilar binarios
log "Compilando binarios..."
cd "$PROJECT_DIR"
go mod download
go build -o issuer-api ./cmd/platform
go build -o notifications ./cmd/notifications
go build -o pending-publisher ./cmd/pending_publisher
go build -o migrate ./cmd/migrate

# Crear configuración
log "Creando configuración..."
cat > .env-issuer << ENVCONF
ISSUER_SERVER_URL=http://localhost:3001
ISSUER_SERVER_PORT=3001
ISSUER_API_AUTH_USER=user-issuer
ISSUER_API_AUTH_PASSWORD=password-issuer
ISSUER_ETHEREUM_URL=https://rpc-amoy.polygon.technology
ISSUER_ETHEREUM_CONTRACT_ADDRESS=0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124
ISSUER_PUBLISH_KEY_PATH=pbkey
ISSUER_ETHEREUM_TRANSFER_ACCOUNT_KEY_PATH=pbkey
ISSUER_ONCHAIN_PUBLISH_STATE_FREQUENCY=1m
ISSUER_ONCHAIN_CHECK_STATUS_FREQUENCY=1m
ISSUER_DATABASE_URL=postgres://issuernode:issuernode_password@localhost:5432/issuernode_db?sslmode=disable
ISSUER_CACHE_PROVIDER=redis
ISSUER_CACHE_URL=redis://localhost:6379
ISSUER_KMS_BJJ_PROVIDER=vault
ISSUER_KMS_ETH_PROVIDER=vault
ISSUER_KEY_STORE_ADDRESS=http://127.0.0.1:8200
ISSUER_KEY_STORE_TOKEN=$ROOT_TOKEN
ISSUER_VAULT_TOKEN=$ROOT_TOKEN
ISSUER_KEY_STORE_PLUGIN_IDEN3_MOUNT_PATH=secret
ISSUER_VAULT_TLS_ENABLED=false
ISSUER_LOG_LEVEL=debug
ISSUER_LOG_MODE=2
ISSUER_ENVIRONMENT=local
ISSUER_ISSUER_NAME=my issuer
ISSUER_ISSUER_LOGO=
ISSUER_IPFS_GATEWAY_URL=https://ipfs.io
ISSUER_UNIVERSAL_DID_RESOLVER_URL=https://dev.uniresolver.io/1.0/identifiers
ISSUER_RESOLVER_PATH=./resolvers_settings.yaml
ISSUER_CIRCUIT_PATH=./pkg/credentials/circuits
ISSUER_PROVER_TIMEOUT=600s
ISSUER_SCHEMA_CACHE=false
ISSUER_MEDIA_TYPE_MANAGER_ENABLED=true
ISSUER_KMS_PROVIDER_LOCAL_STORAGE_FILE_PATH=./localstoragekeys
ENVCONF

# Crear resolvers configuration
cat > resolvers_settings.yaml << 'RESOLVERCONF'
polygon:amoy:
  networkURL: https://rpc-amoy.polygon.technology
  chainID: 80002
  contractAddress: "0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124"
  method: "polygonid"
RESOLVERCONF

# Ejecutar migraciones
log "Ejecutando migraciones..."
source .env-issuer
./migrate up

# Generar clave Ethereum automáticamente
log "Generando clave Ethereum..."
ETH_PRIVATE_KEY=$(openssl rand -hex 32)
vault kv put secret/pbkey privateKey="$ETH_PRIVATE_KEY"

log "Guardando información importante..."
cat > $HOME/issuer-node-info.txt << INFOFILE
INSTALACION COMPLETADA - PRIVADO ID ISSUER-NODE
===============================================

Directorio del proyecto: $PROJECT_DIR

CREDENCIALES:
- API Usuario: user-issuer
- API Password: password-issuer
- Vault Token: $ROOT_TOKEN
- Vault Unseal Key: $UNSEAL_KEY

CLAVE ETHEREUM GENERADA:
- Clave privada: $ETH_PRIVATE_KEY
- IMPORTANTE: Importa esta clave en MetaMask para obtener MATIC de testnet

SERVICIOS:
- API: http://localhost:3001
- Vault UI: http://127.0.0.1:8200
- PostgreSQL: localhost:5432
- Redis: localhost:6379

PARA INICIAR EL SISTEMA:
1. cd $PROJECT_DIR
2. ./start-all.sh

PARA OBTENER MATIC DE TESTNET:
1. Importar la clave privada en MetaMask
2. Ir a https://faucet.polygon.technology/
3. Solicitar MATIC para la red Polygon Amoy

PARA VERIFICAR ESTADO:
- ./status.sh
- ./test-issuer-node.sh

LOGS:
- tail -f logs/api.log
- tail -f logs/notifications.log  
- tail -f logs/publisher.log
INFOFILE

chmod 600 $HOME/issuer-node-info.txt

log "Instalacion completada exitosamente!"
echo ""
echo "INFORMACION IMPORTANTE guardada en: $HOME/issuer-node-info.txt"
echo ""
echo "PROXIMOS PASOS:"
echo "1. cd $PROJECT_DIR"
echo "2. Revisar $HOME/issuer-node-info.txt para credenciales"
echo "3. Obtener MATIC de testnet con la clave Ethereum generada"
echo "4. ./start-all.sh para iniciar el sistema"
echo ""
echo "CLAVE ETHEREUM GENERADA (guardar en lugar seguro):"
echo "$ETH_PRIVATE_KEY"
EOF

chmod +x install-complete.sh
```

---

## 🔄 Mantenimiento

### Script de Backup Automático

```bash
cat > backup-system.sh << 'EOF'
#!/bin/bash

BACKUP_DIR="$HOME/issuer-node-backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="issuer-node-backup-$DATE"

echo "Creando backup del sistema Issuer-Node..."

# Crear directorio de backups
mkdir -p "$BACKUP_DIR"

# Backup de configuración
echo "Respaldando configuración..."
tar -czf "$BACKUP_DIR/${BACKUP_NAME}-config.tar.gz" \
    .env-issuer \
    resolvers_settings.yaml \
    *.yaml \
    *.json 2>/dev/null

# Backup de base de datos
echo "Respaldando base de datos..."
if [ -f ".env-issuer" ]; then
    source .env-issuer
    
    # Parsear URL de DB
    db_url_no_proto=${ISSUER_DATABASE_URL#postgres://}
    db_creds_host=${db_url_no_proto%/*}
    
    if [[ $db_creds_host == *"@"* ]]; then
        db_creds=${db_creds_host%@*}
        db_host=${db_creds_host#*@}
        db_user=${db_creds%:*}
        db_password=${db_creds#*:}
        db_name=${db_url_no_proto##*/}
        db_name=${db_name%\?*}
        
        PGPASSWORD="$db_password" pg_dump -h "${db_host%:*}" -U "$db_user" "$db_name" > "$BACKUP_DIR/${BACKUP_NAME}-database.sql"
        
        if [ $? -eq 0 ]; then
            gzip "$BACKUP_DIR/${BACKUP_NAME}-database.sql"
            echo "Base de datos respaldada exitosamente"
        else
            echo "Error al respaldar base de datos"
        fi
    fi
fi

# Backup de Vault data
echo "Respaldando datos de Vault..."
if [ -d "$HOME/vault-data" ]; then
    tar -czf "$BACKUP_DIR/${BACKUP_NAME}-vault.tar.gz" -C "$HOME" vault-data vault-config
    echo "Datos de Vault respaldados"
fi

# Backup de logs recientes
echo "Respaldando logs..."
if [ -d "logs" ]; then
    find logs -name "*.log" -mtime -7 -exec tar -czf "$BACKUP_DIR/${BACKUP_NAME}-logs.tar.gz" {} +
    echo "Logs respaldados"
fi

# Información del backup
cat > "$BACKUP_DIR/${BACKUP_NAME}-info.txt" << BACKUPINFO
BACKUP INFORMATION
==================
Date: $(date)
System: $(uname -a)
User: $(whoami)
Directory: $(pwd)

FILES INCLUDED:
- Configuration files (.env-issuer, resolvers_settings.yaml)
- Database dump (PostgreSQL)
- Vault data and configuration
- Recent logs (last 7 days)

RESTORATION:
1. Extract configuration: tar -xzf ${BACKUP_NAME}-config.tar.gz
2. Restore database: gunzip ${BACKUP_NAME}-database.sql.gz && psql ... < ${BACKUP_NAME}-database.sql
3. Extract vault data: tar -xzf ${BACKUP_NAME}-vault.tar.gz -C $HOME/
4. Extract logs: tar -xzf ${BACKUP_NAME}-logs.tar.gz
BACKUPINFO

echo ""
echo "Backup completado: $BACKUP_NAME"
echo "Ubicacion: $BACKUP_DIR"
echo "Archivos creados:"
ls -lah "$BACKUP_DIR/${BACKUP_NAME}"*

# Limpiar backups antiguos (mantener solo los ultimos 10)
echo ""
echo "Limpiando backups antiguos..."
cd "$BACKUP_DIR"
ls -t issuer-node-backup-* | tail -n +11 | xargs rm -f 2>/dev/null
echo "Manteniendo los 10 backups mas recientes"
EOF

chmod +x backup-system.sh
```

### Script de Actualización

```bash
cat > update-system.sh << 'EOF'
#!/bin/bash

echo "Actualizando Privado ID Issuer-Node..."

# Crear backup antes de actualizar
echo "Creando backup de seguridad..."
./backup-system.sh

# Detener servicios
echo "Deteniendo servicios..."
./stop-all.sh

# Actualizar código fuente
echo "Actualizando código fuente..."
git fetch origin
git pull origin main

# Actualizar dependencias Go
echo "Actualizando dependencias..."
go mod tidy
go mod download

# Recompilar binarios
echo "Recompilando binarios..."
./compile-all.sh

# Ejecutar migraciones pendientes
echo "Ejecutando migraciones..."
./run-migrations.sh

# Verificar configuración
echo "Verificando configuración..."
./validate-config.sh

# Reiniciar servicios
echo "Reiniciando servicios..."
./start-all.sh

# Ejecutar tests
echo "Ejecutando tests post-actualización..."
sleep 10
./test-issuer-node.sh

echo ""
echo "Actualización completada"
echo "Verifica el estado del sistema con: ./status.sh"
EOF

chmod +x update-system.sh
```

---

##  Seguridad y Consideraciones

### Consideraciones de Seguridad

1. **Variables de Entorno Sensibles**:
   - Nunca commites archivos .env-issuer a repositorios
   - Usa permisos restrictivos (600) para archivos de configuración
   - Rota tokens y contraseñas regularmente

2. **Claves Criptográficas**:
   - Las claves privadas Ethereum deben tener fondos limitados
   - Usa Vault en modo producción con autenticación robusta
   - Implementa backup seguro de claves críticas

3. **Red y Firewall**:
   - Expone solo puertos necesarios
   - Usa HTTPS en producción
   - Implementa rate limiting

4. **Base de Datos**:
   - Usa conexiones SSL en producción
   - Implementa backup automático
   - Limita conexiones concurrentes

### Checklist de Producción

```bash
cat > production-checklist.md << 'EOF'
# Checklist de Producción - Privado ID Issuer-Node

## Pre-despliegue

- [ ] Servidor con recursos suficientes (4+ CPU cores, 8+ GB RAM)
- [ ] Sistema operativo actualizado y hardened
- [ ] Firewall configurado (solo puertos necesarios)
- [ ] Certificados SSL válidos
- [ ] Dominio y DNS configurados
- [ ] Monitoreo del sistema implementado

## Configuración de Seguridad

- [ ] Contraseñas por defecto cambiadas
- [ ] Variables sensibles en archivos con permisos 600
- [ ] Vault con autenticación robusta (no solo root token)
- [ ] Base de datos con SSL habilitado
- [ ] Logs configurados apropiadamente (no debug en prod)
- [ ] Backup automático configurado

## Variables de Entorno Críticas

- [ ] ISSUER_SERVER_URL apunta al dominio real
- [ ] ISSUER_API_AUTH_* con credenciales fuertes
- [ ] ISSUER_ETHEREUM_URL con RPC privado (Infura/Alchemy)
- [ ] ISSUER_LOG_LEVEL=info (no debug)
- [ ] ISSUER_ENVIRONMENT=production

## Testing Pre-producción

- [ ] Todos los tests pasan
- [ ] Benchmark de performance aceptable
- [ ] Pruebas de carga realizadas
- [ ] Tiempo de respuesta < 2 segundos
- [ ] Pruebas de failover realizadas

## Post-despliegue

- [ ] Monitoreo de salud configurado
- [ ] Alertas de error configuradas
- [ ] Backup funcionando
- [ ] Logs centralizados
- [ ] Documentación actualizada
- [ ] Equipo entrenado en troubleshooting

## Mantenimiento Continuo

- [ ] Actualizaciones de seguridad automáticas
- [ ] Rotación de credenciales programada
- [ ] Revisiones de seguridad periódicas
- [ ] Testing de disaster recovery
- [ ] Optimización de performance continua
EOF
```

### Monitoreo y Alertas

```bash
cat > monitoring.sh << 'EOF'
#!/bin/bash

# Script de monitoreo básico para Issuer-Node

ALERT_EMAIL="admin@example.com"
LOG_FILE="monitoring.log"

# Función para alertas
send_alert() {
    local subject="$1"
    local message="$2"
    
    echo "$(date): ALERT - $subject" >> "$LOG_FILE"
    echo "$message" >> "$LOG_FILE"
    
    # Enviar email si mail está disponible
    if command -v mail >/dev/null 2>&1; then
        echo "$message" | mail -s "$subject" "$ALERT_EMAIL"
    fi
    
    # Log local
    logger "ISSUER_NODE_ALERT: $subject - $message"
}

# Verificar servicios críticos
check_service() {
    local service="$1"
    local pid_file="pids/$service.pid"
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ! kill -0 "$pid" 2>/dev/null; then
            send_alert "Servicio Caído: $service" "El servicio $service (PID: $pid) no está ejecutándose"
            return 1
        fi
    else
        send_alert "Servicio Sin PID: $service" "No se encontró archivo PID para $service"
        return 1
    fi
    
    return 0
}

# Verificar conectividad API
check_api() {
    local api_url="http://localhost:3001/health"
    
    if ! curl -s --max-time 5 "$api_url" > /dev/null; then
        send_alert "API No Responde" "La API en $api_url no responde"
        return 1
    fi
    
    return 0
}

# Verificar uso de recursos
check_resources() {
    # Verificar uso de memoria
    local mem_usage=$(free | grep Mem | awk '{print ($3/$2)*100}')
    if (( $(echo "$mem_usage > 90" | bc -l) )); then
        send_alert "Memoria Alta" "Uso de memoria: ${mem_usage}%"
    fi
    
    # Verificar uso de disco
    local disk_usage=$(df . | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 85 ]; then
        send_alert "Disco Lleno" "Uso de disco: ${disk_usage}%"
    fi
}

# Ejecutar verificaciones
echo "$(date): Iniciando verificaciones de monitoreo" >> "$LOG_FILE"

check_service "api"
check_service "notifications"
check_service "publisher"
check_api
check_resources

echo "$(date): Verificaciones completadas" >> "$LOG_FILE"
EOF

chmod +x monitoring.sh

# Agregar a crontab para ejecutar cada 5 minutos
echo "Para monitoreo automático, agregar a crontab:"
echo "*/5 * * * * cd $PWD && ./monitoring.sh"
```

## Conclusión

Esta guía completa proporciona todos los pasos necesarios para instalar, configurar y mantener el Privado ID Issuer-Node de forma nativa en Linux sin Docker. Incluye:

- Instalación paso a paso de todas las dependencias
- Scripts de automatización para simplificar tareas comunes
- Herramientas de diagnóstico y troubleshooting
- Consideraciones de seguridad y producción
- Procedimientos de backup y mantenimiento

### Próximos Pasos Recomendados

1. **Ejecutar la instalación automatizada**: `./install-complete.sh`
2. **Obtener MATIC de testnet** para la clave Ethereum generada
3. **Iniciar el sistema**: `./issuer-node-manager.sh start`
4. **Verificar funcionamiento**: `./issuer-node-manager.sh test`
5. **Configurar monitoreo** para producción

### Soporte y Recursos

- **Documentación oficial**: https://docs.privado.id
- **Repositorio GitHub**: https://github.com/0xPolygonID/issuer-node  
- **Faucet Polygon Amoy**: https://faucet.polygon.technology/
- **Comunidad Discord**: Privado ID Community

**Recuerda**: Esta instalación es para desarrollo y testing. Para producción, revisa el checklist de seguridad y implementa las medidas adicionales necesarias.
EOF

chmod +x benchmark.sh
```

---

##  Troubleshooting

### Problemas Comunes y Soluciones

#### 1. Errores de Compilación

```bash
cat > fix-compilation-issues.sh << 'EOF'
#!/bin/bash

echo " Solucionando problemas de compilación..."

# Verificar versión de Go
GO_VERSION=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | head -1)
echo "📊 Versión de Go detectada: $GO_VERSION"

if [[ ! "$GO_VERSION" > "go1.20" ]]; then
    echo "❌ Se requiere Go 1.21 o superior"
    echo " Actualiza Go desde: https://golang.org/dl/"
    exit ;
fi

# Limpiar caché
echo "Limpiando cache de Go..."
go clean -cache -modcache -i -r

# Verificar conectividad a módulos
echo "Verificando conectividad a módulos Go..."
go env GOPROXY

# Recargar dependencias
echo "📦 Recargando dependencias..."
rm -f go.sum
go mod tidy
go mod download

# Verificar integridad
echo "🔍 Verificando integridad de módulos..."
go mod verify

# Intentar compilación de prueba
echo " Compilación de prueba..."
go build -v ./cmd/platform > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo " Compilación exitosa"
else
    echo " Problemas de compilación detectados"
    echo ""
    echo " Diagnóstico detallado:"
    go build -v ./cmd/platform
fi
EOF

chmod +x fix-compilation-issues.sh
```

#### 2. Problemas de Base de Datos

```bash
cat > fix-database-issues.sh << 'EOF'
#!/bin/bash

echo "🗄️ Solucionando problemas de base de datos..."

# Verificar servicio PostgreSQL
echo "🔍 Verificando servicio PostgreSQL..."
if systemctl is-active --quiet postgresql; then
    echo " PostgreSQL está ejecutándose"
else
    echo "⚙️ Iniciando PostgreSQL..."
    sudo systemctl start postgresql
    sleep 3
fi

# Verificar usuario y base de datos
echo "🔍 Verificando configuración de usuario..."

# Recrear usuario y base de datos
sudo -u postgres psql << 'EOSQL'
-- Verificar si el usuario existe
DO $
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'issuernode') THEN
        CREATE USER issuernode WITH PASSWORD 'issuernode_password';
        RAISE NOTICE 'Usuario issuernode creado';
    ELSE
        RAISE NOTICE 'Usuario issuernode ya existe';
    END IF;
END
$;

-- Verificar si la base de datos existe
SELECT 'CREATE DATABASE issuernode_db OWNER issuernode'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'issuernode_db')\gexec

-- Otorgar permisos
GRANT ALL PRIVILEGES ON DATABASE issuernode_db TO issuernode;
ALTER USER issuernode CREATEDB;

\q
EOSQL

# Verificar configuración de autenticación
echo "Verificando configuración de autenticación..."

PG_VERSION=$(sudo -u postgres psql -t -c "SELECT version();" | grep -oE '[0-9]+\.[0-9]+' | head -1)
PG_HBA_FILE="/etc/postgresql/$PG_VERSION/main/pg_hba.conf"

if [ -f "$PG_HBA_FILE" ]; then
    # Hacer backup
    sudo cp "$PG_HBA_FILE" "$PG_HBA_FILE.backup.$(date +%Y%m%d)"
    
    # Configurar método md5
    sudo sed -i 's/local   all             all                                     peer/local   all             all                                     md5/' "$PG_HBA_FILE"
    sudo sed -i 's/host    all             all             127.0.0.1\/32            ident/host    all             all             127.0.0.1\/32            md5/' "$PG_HBA_FILE"
    
    # Reiniciar PostgreSQL
    sudo systemctl restart postgresql
    sleep 3
    
    echo "✅ Configuración de autenticación actualizada"
else
    echo "⚠️ Archivo pg_hba.conf no encontrado en ubicación estándar"
fi

# Test de conexión
echo " Probando conexión..."
if PGPASSWORD=issuernode_password psql -h localhost -U issuernode -d issuernode_db -c "SELECT 'Conexión exitosa' as resultado;"; then
    echo " Conexión a base de datos exitosa"
else
    echo "❌ No se pudo conectar a la base de datos"
    echo ""
    echo "🔍 Información adicional para debugging:"
    sudo systemctl status postgresql --no-pager -l
fi
EOF

chmod +x fix-database-issues.sh
```

#### 3. Problemas de Red y Conectividad

```bash
cat > fix-network-issues.sh << 'EOF'
#!/bin/bash

echo "Solucionando problemas de red y conectividad..."

# Verificar puertos en uso
echo " Verificando puertos..."

check_port() {
    local port=$1
    local service_name=$2
    
    if netstat -tuln 2>/dev/null | grep -q ":$port "; then
        echo "Puerto $port ($service_name): En uso"
        
        # Mostrar qué proceso está usando el puerto
        local process=$(lsof -ti:$port 2>/dev/null)
        if [ -n "$process" ]; then
            echo "  📊 Proceso: PID $process ($(ps -p $process -o comm= 2>/dev/null))"
        fi
    else
        echo "❌ Puerto $port ($service_name): Libre o no disponible"
    fi
}

check_port 3001 "API Issuer-Node"
check_port 5432 "PostgreSQL"
check_port 6379 "Redis"
check_port 8200 "Vault"

# Test de conectividad externa
echo ""
echo " Probando conectividad externa..."

# Test DNS
if nslookup google.com > /dev/null 2>&1; then
    echo " Resolución DNS: Funcionando"
else
    echo "❌ Resolución DNS: Problema"
fi

# Test conectividad HTTP
if curl -s --connect-timeout 5 https://httpbin.org/get > /dev/null; then
    echo " Conectividad HTTPS: Funcionando"
else
    echo "❌ Conectividad HTTPS: Problema"
fi

# Test RPC blockchain
if [ -f ".env-issuer" ]; then
    source .env-issuer
    
    if [ -n "$ISSUER_ETHEREUM_URL" ]; then
        echo ""
        echo "⛓️ Probando conectividad blockchain..."
        
        if curl -s --connect-timeout 10 -X POST -H "Content-Type: application/json" \
            --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
            "$ISSUER_ETHEREUM_URL" | grep -q '"result"'; then
            echo " RPC Polygon: Respondiendo"
        else
            echo "❌ RPC Polygon: No responde"
            echo " Verifica la URL: $ISSUER_ETHEREUM_URL"
        fi
    fi
fi

# Verificar firewall
echo ""
echo " Verificando configuración de firewall..."

if command -v ufw >/dev/null 2>&1; then
    local ufw_status=$(sudo ufw status | head -1)
    echo "UFW: $ufw_status"
    
    if [[ "$ufw_status" == *"active"* ]]; then
        echo " Si tienes problemas de conectividad, considera:"
        echo "  sudo ufw allow 3001/tcp  # Para API"
        echo "  sudo ufw allow from 127.0.0.1  # Para servicios locales"
    fi
elif command -v firewalld >/dev/null 2>&1; then
    local firewalld_status=$(sudo firewall-cmd --state 2>/dev/null)
    echo "FirewallD: $firewalld_status"
else
    echo "No se detectó firewall configurado"
fi

# Test de interfaces de red
echo ""
echo " Información de interfaces de red..."
ip addr show | grep -E "(inet |UP,)" | head -10
EOF

chmod +x fix-network-issues.sh
```

#### 4. Problemas de Memoria y Performance

```bash
cat > fix-performance-issues.sh << 'EOF'
#!/bin/bash

echo " Diagnosticando y solucionando problemas de performance..."

# Verificar recursos del sistema
echo "📊 Recursos del sistema:"
echo "  CPU: $(nproc) cores"
echo "  RAM: $(free -h | grep Mem | awk '{print $2}') total, $(free -h | grep Mem | awk '{print $7}') disponible"
echo "  Swap: $(free -h | grep Swap | awk '{print $2}') total, $(free -h | grep Swap | awk '{print $4}') disponible"
echo "  Disco: $(df -h . | tail -1 | awk '{print $4}') disponible"

# Verificar uso de memoria por procesos
echo ""
echo " Uso de memoria por procesos del issuer-node:"

for service in api notifications publisher; do
    if [ -f "pids/$service.pid" ]; then
        local pid=$(cat "pids/$service.pid")
        if kill -0 "$pid" 2>/dev/null; then
            local mem_info=$(ps -p "$pid" -o pid,ppid,%mem,rss,vsz,comm --no-headers)
            echo "  $service: $mem_info"
            
            # Advertir si usa mucha memoria
            local rss=$(echo $mem_info | awk '{print $4}')
            if [ "$rss" -gt 500000 ]; then  # > 500MB
                echo "    ⚠️ Alto uso de memoria: ${rss}KB"
            fi
        fi
    fi
done

# Verificar procesos que más consumen memoria
echo ""
echo "🔍 Top 5 procesos por uso de memoria:"
ps aux --sort=-%mem | head -6

# Verificar I/O de disco
echo ""
echo "💿 Información de I/O de disco:"
if command -v iostat >/dev/null 2>&1; then
    iostat -x 1 1 | grep -E "(Device|$(df . | tail -1 | awk '{print $1}' | sed 's|/dev/||'))"
else
    echo "  iostat no disponible (instalar con: sudo apt install sysstat)"
fi

# Verificar logs por errores de memoria
echo ""
echo "🔍 Buscando errores relacionados con memoria en logs..."

if [ -d "logs" ]; then
    for log_file in logs/*.log; do
        if [ -f "$log_file" ]; then
            local mem_errors=$(grep -i -E "(out of memory|oom|memory leak|fatal|panic)" "$log_file" | wc -l)
            if [ $mem_errors -gt 0 ]; then
                echo "  ⚠️ $log_file: $mem_errors posibles errores de memoria"
                echo "    Últimos errores:"
                grep -i -E "(out of memory|oom|memory leak|fatal|panic)" "$log_file" | tail -3 | while read line; do
                    echo "      $line"
                done
            fi
        fi
    done
else
    echo "  No se encontró directorio de logs"
fi

# Recomendaciones de optimización
echo ""
echo " Recomendaciones de optimización:"

# Verificar swap
local swap_used=$(free | grep Swap | awk '{print $3}')
if [ "$swap_used" -gt 100000 ]; then  # > 100MB swap usado
    echo "  ⚠️ Se está usando swap ($((swap_used/1024))MB) - considera añadir más RAM"
fi

# Verificar número de conexiones de base de datos
if [ -f ".env-issuer" ]; then
    source .env-issuer
    
    if [[ "$ISSUER_DATABASE_URL" =~ postgres:// ]]; then
        echo "   Para PostgreSQL:"
        echo "    - Ajustar shared_buffers (recomendado: 25% de RAM total)"
        echo "    - Limitar conexiones concurrentes"
        echo "    - Usar connection pooling si es necesario"
    fi
fi

# Sugerencias específicas para issuer-node
echo "   Para Issuer-Node:"
echo "    - Ajustar ISSUER_PROVER_TIMEOUT si las pruebas ZK toman mucho tiempo"
echo "    - Usar ISSUER_LOG_LEVEL=info en producción (en lugar de debug)"
echo "    - Configurar límites de memoria en systemd si es necesario"
echo "    - Monitorear el tamaño de la base de datos regularmente"

# Script para liberar memoria cache
echo ""
echo " Para liberar memoria cache del sistema (úsalo con cuidado):"
echo "  sudo sync && sudo sysctl vm.drop_caches=3"

# Información de límites del sistema
echo ""
echo "⚙️ Límites del sistema para el usuario actual:"
echo "  Archivos abiertos: $(ulimit -n)"
echo "  Procesos: $(ulimit -u)"
echo "  Memoria virtual: $(ulimit -v) KB"
EOF

chmod +x fix-performance-issues.sh
```

---

##  Scripts de Automatización

### Script Maestro de Gestión

```bash
cat > issuer-node-manager.sh << 'EOF'
#!/bin/bash

# Privado ID Issuer-Node Manager
# Script maestro para gestionar el issuer-node

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
show_banner() {
    echo -e "${PURPLE}"
    echo "██████╗ ██████╗ ██╗██╗   ██╗ █████╗ ██████╗  ██████╗     ██╗██████╗ "
    echo "██╔══██╗██╔══██╗██║██║   ██║██╔══██╗██╔══██╗██╔═══██╗    ██║██╔══██╗"
    echo "██████╔╝██████╔╝██║██║   ██║███████║██║  ██║██║   ██║    ██║██║  ██║"
    echo "██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══██║██║  ██║██║   ██║    ██║██║  ██║"
    echo "██║     ██║  ██║██║ ╚████╔╝ ██║  ██║██████╔╝╚██████╔╝    ██║██████╔╝"
    echo "╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═════╝  ╚═════╝     ╚═╝╚═════╝ "
    echo -e "${NC}"
    echo -e "${CYAN}Issuer-Node Manager v$VERSION - Native Installation${NC}"
    echo -e "${CYAN}==========================================================${NC}"
    echo ""
}

# Ayuda
show_help() {
    echo " Uso: $0 [COMANDO] [OPCIONES]"
    echo ""
    echo "" COMANDOS PRINCIPALES:"
    echo "  setup          Configuración inicial completa"
    echo "  start          Iniciar todos los servicios"
    echo "  stop           Detener todos los servicios"
    echo "  restart        Reiniciar todos los servicios"
    echo "  status         Mostrar estado de servicios"
    echo "  logs           Mostrar logs en tiempo real"
    echo ""
    echo "🛠️ COMANDOS DE MANTENIMIENTO:"
    echo "  compile        Recompilar binarios"
    echo "  migrate        Ejecutar migraciones de DB"
    echo "  backup         Crear backup de datos"
    echo "  restore        Restaurar backup"
    echo "  clean          Limpiar datos temporales"
    echo ""
    echo "🧪 COMANDOS DE TESTING:"
    echo "  test           Ejecutar tests básicos"
    echo "  benchmark      Ejecutar benchmark de performance"
    echo "  validate       Validar configuración"
    echo ""
    echo "🔧 COMANDOS DE DIAGNÓSTICO:"
    echo "  doctor         Diagnóstico completo del sistema"
    echo "  fix-db         Reparar problemas de base de datos"
    echo "  fix-network    Reparar problemas de red"
    echo "  fix-perf       Diagnosticar problemas de performance"
    echo ""
    echo "ℹ️ INFORMACIÓN:"
    echo "  version        Mostrar versión"
    echo "  help           Mostrar esta ayuda"
    echo ""
    echo "📖 Ejemplos:"
    echo "  $0 setup              # Configuración inicial completa"
    echo "  $0 start --verbose    # Iniciar con logs verbosos"
    echo "  $0 logs --service api # Ver solo logs de la API"
    echo "  $0 backup --name prod_backup # Crear backup con nombre específico"
}

# Ejecutar comando con logging
run_command() {
    local cmd="$1"
    local description="$2"
    local log_file="$3"
    
    echo -e "${BLUE} $description...${NC}"
    
    if [ -n "$log_file" ]; then
        if eval "$cmd" >> "$log_file" 2>&1; then
            echo -e "${GREEN} $description completado${NC}"
            return 0
        else
            echo -e "${RED}❌ Error en: $description${NC}"
            echo -e "${YELLOW} Ver logs: tail -f $log_file${NC}"
            return 1
        fi
    else
        if eval "$cmd"; then
            echo -e "${GREEN} $description completado${NC}"
            return 0
        else
            echo -e "${RED}❌ Error en: $description${NC}"
            return 1
        fi
    fi
}

# Función principal
main() {
    local command="${1:-help}"
    shift
    
    # Crear directorio de logs si no existe
    mkdir -p logs
    
    case "$command" in
        "setup")
            show_banner
            echo -e "${YELLOW} Iniciando configuración completa...${NC}"
            echo ""
            
            # Verificar sistema
            run_command "uname -a" "Verificando sistema"
            run_command "go version" "Verificando Go"
            
            # Configurar servicios
            run_command "$HOME/redis-control.sh start" "Iniciando Redis"
            run_command "$HOME/vault-control.sh start" "Iniciando Vault"
            run_command "$HOME/vault-control.sh init" "Inicializando Vault"
            run_command "$HOME/vault-control.sh unseal" "Desbloqueando Vault"
            run_command "$HOME/vault-control.sh login" "Autenticando Vault"
            run_command "$HOME/vault-control.sh setup-kv" "Configurando Vault KV"
            
            # Compilar y configurar
            run_command "./compile-all.sh" "Compilando binarios"
            run_command "./run-migrations.sh" "Ejecutando migraciones"
            run_command "./setup-vault-keys.sh" "Configurando claves"
            run_command "./validate-config.sh" "Validando configuración"
            
            echo ""
            echo -e "${GREEN} Configuración completada exitosamente${NC}"
            echo -e "${CYAN}💡 Próximo paso: $0 start${NC}"
            ;;
            
        "start")
            echo -e "${GREEN} Iniciando Issuer-Node...${NC}"
            run_command "./start-all.sh" "Iniciando servicios"
            ;;
            
        "stop")
            echo -e "${YELLOW} Deteniendo Issuer-Node...${NC}"
            run_command "./stop-all.sh" "Deteniendo servicios"
            ;;
            
        "restart")
            echo -e "${YELLOW} Reiniciando Issuer-Node...${NC}"
            run_command "./stop-all.sh" "Deteniendo servicios"
            sleep 3
            run_command "./start-all.sh" "Iniciando servicios"
            ;;
            
        "status")
            run_command "./status.sh" "Verificando estado"
            ;;
            
        "logs")
            local service="$1"
            if [ -n "$service" ]; then
                if [ -f "logs/$service.log" ]; then
                    tail -f "logs/$service.log"
                else
                    echo -e "${RED}❌ Log no encontrado para servicio: $service${NC}"
                    echo -e "${YELLOW} Servicios disponibles: api, notifications, publisher${NC}"
                fi
            else
                echo -e "${BLUE} Mostrando todos los logs...${NC}"
                tail -f logs/*.log
            fi
            ;;
            
        "compile")
            run_command "./compile-all.sh" "Recompilando binarios"
            ;;
            
        "migrate")
            run_command "./run-migrations.sh" "Ejecutando migraciones"
            ;;
            
        "test")
            run_command "./test-issuer-node.sh" "Ejecutando tests"
            ;;
            
        "benchmark")
            run_command "./benchmark.sh" "Ejecutando benchmark"
            ;;
            
        "validate")
            run_command "./validate-config.sh" "Validando configuración"
            ;;
            
        "doctor")
            echo -e "${BLUE} Ejecutando diagnóstico completo...${NC}"
            echo ""
            
            echo -e "${CYAN}📊 Sistema:${NC}"
            uname -a
            echo ""
            
            echo -e "${CYAN} Recursos:${NC}"
            free -h
            df -h .
            echo ""
            
            echo -e "${CYAN}🔍 Servicios:${NC}"
            ./status.sh
            echo ""
            
            echo -e "${CYAN} Tests:${NC}"
            ./test-issuer-node.sh
            ;;
            
        "fix-db")
            run_command "./fix-database-issues.sh" "Reparando base de datos"
            ;;
            
        "fix-network")
            run_command "./fix-network-issues.sh" "Reparando red"
            ;;
            
        "fix-perf")
            run_command "./fix-performance-issues.sh" "Diagnosticando performance"
            ;;
            
        "backup")
            local backup_name="${1:-backup_$(date +%Y%m%d_%H%M%S)}"
            echo -e "${BLUE} Creando backup: $backup_name${NC}"
            
            mkdir -p backups
            
            # Backup de configuración
            tar -czf "backups/${backup_name}_config.tar.gz" .env-issuer resolvers_settings.yaml 2>/dev/null
            
            # Backup de Vault (si está disponible)
            if curl -s http://127.0.0.1:8200/v1/sys/health > /dev/null; then
                cp -r "$HOME/vault-data" "backups/${backup_name}_vault_data" 2>/dev/null
            fi
            
            echo -e "${GREEN} Backup creado en backups/${backup_name}_*${NC}"
            ;;
            
        "clean")
            echo -e "${YELLOW} Limpiando datos temporales...${NC}"
            
            # Limpiar logs antiguos
            find logs/ -name "*.log" -mtime +7 -delete 2>/dev/null
            
            # Limpiar PIDs stale
            rm -f pids/*.pid
            
            # Limpiar caché Go
            go clean -cache -modcache 2>/dev/null
            
            echo -e "${GREEN} Limpieza completada${NC}"
            ;;
            
        "version")
            echo "Issuer-Node Manager v$VERSION"
            echo "Privado ID Issuer-Node - Native Installation"
            ;;
            
        "help"|*)
            show_help
            ;;
    esac
}

# Verificar que estamos en el directorio correcto
if [ ! -f "go.mod" ] || ! grep -q "github.com/polygonid/sh-id-platform" go.mod 2>/dev/null; then
    echo -e "${RED}❌ Error: No estás en el directorio raíz del proyecto issuer-node${NC}"
    echo -e "${YELLOW} Ejecuta: cd \$HOME/privado-id-development/issuer-node${NC}"
    exit 1
fi

# Ejecutar función principal con todos los argumentos
main "$@"
EOF

chmod +x issuer-node-manager.sh
```

### Script de Instalación Automatizada Completa

```bash
cat > install-complete.sh << 'EOF'
#!/bin/bash

# Script de instalación completamente automatizada
# Instala todo desde cero sin intervención del usuario

set -e  # Salir en caso de error

echo " Instalación Automatizada Completa - Privado ID Issuer-Node"
echo "=============================================================="
echo ""

# Configuración
export DEBIAN_FRONTEND=noninteractive
INSTALL_DIR="$HOME/privado-id-development"
PROJECT_DIR="$INSTALL_DIR/issuer-node"

# Función para log
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Actualizar sistema
log "Actualizando sistema..."
sucleanup() {
    echo ""
    echo " Deteniendo todos los servicios..."
    
    # Leer PIDs de archivos y matar procesos
    for service in api notifications publisher; do
        if [ -f "$PID_DIR/$service.pid" ]; then
            pid=$(cat "$PID_DIR/$service.pid")
            if kill -0 "$pid" 2>/dev/null; then
                echo "   Deteniendo $service (PID: $pid)..."
                kill "$pid"
                
                # Esperar terminación limpia
                local count=0
                while kill -0 "$pid" 2>/dev/null && [ $count -lt 10 ]; do
                    sleep 1
                    count=$((count + 1))
                done
                
                # Forzar si no terminó
                if kill -0 "$pid" 2>/dev/null; then
                    echo "  ⚠️ Forzando terminación de $service..."
                    kill -9 "$pid"
                fi
            fi
            rm -f "$PID_DIR/$service.pid"
        fi
    done
    
    echo " Todos los servicios detenidos"
    exit 0
}

# Registrar función de limpieza
trap cleanup SIGINT SIGTERM EXIT

# Función para iniciar servicio en background
start_service() {
    local name=$1
    local script=$2
    local display_name=$3
    
    echo " Iniciando $display_name..."
    
    if [ ! -x "$script" ]; then
        echo "❌ Script $script no encontrado o no ejecutable"
        exit 1
    fi
    
    # Iniciar servicio en background
    nohup "$script" > "$LOG_DIR/$name.log" 2>&1 &
    local pid=$!
    
    # Guardar PID
    echo "$pid" > "$PID_DIR/$name.pid"
    
    # Verificar que inició correctamente
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
        echo "   $display_name iniciado (PID: $pid)"
    else
        echo "  ❌ Error iniciando $display_name"
        echo "  🔍 Revisa el log: tail -f $LOG_DIR/$name.log"
        exit 1
    fi
}

# Función para verificar salud de servicios
check_service_health() {
    echo ""
    echo " Verificando salud de servicios..."
    
    # Verificar API
    local api_url="${ISSUER_SERVER_URL:-http://localhost:3001}"
    local count=0
    
    echo "  🔍 Esperando que API responda en $api_url..."
    while ! curl -s "$api_url/health" > /dev/null 2>&1 && [ $count -lt 30 ]; do
        sleep 2
        count=$((count + 1))
        if [ $((count % 5)) -eq 0 ]; then
            echo "    ⏳ Esperando... ($count/30)"
        fi
    done
    
    if curl -s "$api_url/health" > /dev/null 2>&1; then
        echo "   API respondiendo correctamente"
    else
        echo "  ⚠️ API no responde después de 60s (puede estar iniciando)"
    fi
    
    # Verificar procesos
    for service in api notifications publisher; do
        if [ -f "$PID_DIR/$service.pid" ]; then
            local pid=$(cat "$PID_DIR/$service.pid")
            if kill -0 "$pid" 2>/dev/null; then
                echo "   $service ejecutándose (PID: $pid)"
            else
                echo "  ❌ $service no está ejecutándose"
            fi
        fi
    done
}

# Verificar prerrequisitos
echo "🔍 Verificando prerrequisitos..."

# Verificar directorio
if [ ! -f ".env-issuer" ]; then
    echo "❌ Archivo .env-issuer no encontrado"
    echo " Ejecuta: ./initialize-all.sh"
    exit 1
fi

# Cargar configuración
source .env-issuer

# Verificar binarios
for binary in issuer-api notifications pending-publisher; do
    if [ ! -x "./$binary" ]; then
        echo "❌ Binario $binary no encontrado"
        echo " Ejecuta: ./compile-all.sh"
        exit 1
    fi
done

# Verificar servicios de infraestructura
echo " Verificando servicios de infraestructura..."

# Redis
if ! redis-cli -u "$ISSUER_CACHE_URL" ping > /dev/null 2>&1; then
    echo "⚙️ Iniciando Redis..."
    if [ -f "$HOME/redis-control.sh" ]; then
        $HOME/redis-control.sh start
    else
        redis-server --daemonize yes
    fi
    sleep 2
fi

# Vault
if ! curl -s "$ISSUER_KEY_STORE_ADDRESS/v1/sys/health" > /dev/null 2>&1; then
    echo "⚙️ Iniciando Vault..."
    if [ -f "$HOME/vault-control.sh" ]; then
        $HOME/vault-control.sh start
        $HOME/vault-control.sh unseal
    else
        echo "❌ Vault no disponible y script de control no encontrado"
        exit 1
    fi
fi

echo " Prerrequisitos verificados"
echo ""

# Iniciar servicios
echo " Iniciando servicios del Issuer-Node..."

start_service "api" "./start-api.sh" "API Principal"
sleep 3  # Dar tiempo para que la API inicie

start_service "notifications" "./start-notifications.sh" "Servicio de Notificaciones"
sleep 2

start_service "publisher" "./start-publisher.sh" "Publisher de Estados"
sleep 2

# Verificar salud
check_service_health

echo ""
echo " ¡Issuer-Node iniciado exitosamente!"
echo ""
echo " Servicios disponibles:"
echo "   API REST: ${ISSUER_SERVER_URL:-http://localhost:3001}"
echo "   Documentación: ${ISSUER_SERVER_URL:-http://localhost:3001}/api/docs"
echo "   Vault UI: $ISSUER_KEY_STORE_ADDRESS"
echo ""
echo " Credenciales por defecto:"
echo "  API: $ISSUER_API_AUTH_USER / $ISSUER_API_AUTH_PASSWORD"
echo ""
echo " Logs disponibles:"
echo "  tail -f logs/api.log"
echo "  tail -f logs/notifications.log"
echo "  tail -f logs/publisher.log"
echo ""
echo " Para detener: Presiona Ctrl+C o ejecuta: ./stop-all.sh"
echo ""

# Monitor de logs en tiempo real (opcional)
echo "🔍 Monitoreando logs (Ctrl+C para detener monitoreo)..."
echo "$(printf '%.0s=' {1..60})"

# Mostrar logs de todos los servicios
tail -f logs/*.log 2>/dev/null &
TAIL_PID=$!

# Esperar a que el usuario presione Ctrl+C
wait

# Limpiar proceso de tail
kill $TAIL_PID 2>/dev/null
EOF

chmod +x start-all.sh
```

### Paso 3: Script de Detención

```bash
cat > stop-all.sh << 'EOF'
#!/bin/bash

echo " Deteniendo Privado ID Issuer-Node..."

PID_DIR="pids"

# Función para detener un servicio
stop_service() {
    local service=$1
    local display_name=$2
    
    if [ -f "$PID_DIR/$service.pid" ]; then
        local pid=$(cat "$PID_DIR/$service.pid")
        
        if kill -0 "$pid" 2>/dev/null; then
            echo " Deteniendo $display_name (PID: $pid)..."
            
            # Enviar SIGTERM (terminación limpia)
            kill "$pid"
            
            # Esperar terminación limpia (hasta 10 segundos)
            local count=0
            while kill -0 "$pid" 2>/dev/null && [ $count -lt 10 ]; do
                sleep 1
                count=$((count + 1))
            done
            
            # Si no terminó, forzar con SIGKILL
            if kill -0 "$pid" 2>/dev/null; then
                echo "  ⚠️ Forzando terminación de $display_name..."
                kill -9 "$pid"
                sleep 1
            fi
            
            # Verificar que terminó
            if kill -0 "$pid" 2>/dev/null; then
                echo "  ❌ No se pudo detener $display_name"
            else
                echo "   $display_name detenido exitosamente"
            fi
        else
            echo "  ℹ️ $display_name no estaba ejecutándose"
        fi
        
        # Limpiar archivo PID
        rm -f "$PID_DIR/$service.pid"
    else
        echo "  ℹ️ No se encontró PID para $display_name"
    fi
}

# Detener servicios en orden inverso
stop_service "publisher" "Publisher de Estados"
stop_service "notifications" "Servicio de Notificaciones"  
stop_service "api" "API Principal"

# Limpiar directorio de PIDs
rmdir "$PID_DIR" 2>/dev/null

echo ""
echo " Todos los servicios han sido detenidos"

# Mostrar procesos relacionados que puedan seguir ejecutándose
echo ""
echo "🔍 Verificando procesos relacionados..."
if pgrep -f "issuer-api\|notifications\|pending-publisher" > /dev/null; then
    echo "⚠️ Procesos relacionados aún ejecutándose:"
    pgrep -f "issuer-api\|notifications\|pending-publisher" | while read pid; do
        echo "  PID $pid: $(ps -p $pid -o comm= 2>/dev/null)"
    done
    echo ""
    echo " Para forzar terminación: pkill -f 'issuer-api|notifications|pending-publisher'"
else
    echo " No hay procesos relacionados ejecutándose"
fi
EOF

chmod +x stop-all.sh
```

### Paso 4: Script de Estado y Monitoreo

```bash
cat > status.sh << 'EOF'
#!/bin/bash

echo "📊 Estado del Privado ID Issuer-Node"
echo "===================================="

PID_DIR="pids"
LOG_DIR="logs"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Función para mostrar estado de servicio
check_service_status() {
    local service=$1
    local display_name=$2
    local port=$3
    
    echo ""
    echo "🔍 $display_name:"
    
    # Verificar proceso
    if [ -f "$PID_DIR/$service.pid" ]; then
        local pid=$(cat "$PID_DIR/$service.pid")
        
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "  ${GREEN} Proceso${NC}: Ejecutándose (PID: $pid)"
            
            # Mostrar información adicional del proceso
            local cpu_mem=$(ps -p "$pid" -o %cpu,%mem --no-headers 2>/dev/null)
            if [ -n "$cpu_mem" ]; then
                echo "  📊 Recursos: CPU: $(echo $cpu_mem | awk '{print $1}')%, RAM: $(echo $cpu_mem | awk '{print $2}')%"
            fi
            
            # Verificar tiempo de ejecución
            local start_time=$(ps -p "$pid" -o lstart --no-headers 2>/dev/null)
            if [ -n "$start_time" ]; then
                echo "  🕐 Iniciado: $start_time"
            fi
            
        else
            echo -e "  ${RED}❌ Proceso${NC}: No ejecutándose (PID stale: $pid)"
        fi
    else
        echo -e "  ${YELLOW}⚠️ Proceso${NC}: No hay archivo PID"
    fi
    
    # Verificar puerto si se especifica
    if [ -n "$port" ]; then
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
            echo -e "  ${GREEN} Puerto${NC}: $port está en uso"
        else
            echo -e "  ${RED}❌ Puerto${NC}: $port no está en uso"
        fi
    fi
    
    # Verificar log
    if [ -f "$LOG_DIR/$service.log" ]; then
        local log_size=$(du -h "$LOG_DIR/$service.log" 2>/dev/null | cut -f1)
        local log_lines=$(wc -l < "$LOG_DIR/$service.log" 2>/dev/null)
        echo "   Log: $log_size ($log_lines líneas)"
        
        # Mostrar últimas líneas si hay errores recientes
        local recent_errors=$(tail -50 "$LOG_DIR/$service.log" 2>/dev/null | grep -i "error\|fatal\|panic" | wc -l)
        if [ $recent_errors -gt 0 ]; then
            echo -e "  ${YELLOW}⚠️ Errores recientes${NC}: $recent_errors en últimas 50 líneas"
        fi
    else
        echo -e "  ${YELLOW}⚠️ Log${NC}: No encontrado"
    fi
}

# Cargar configuración si existe
if [ -f ".env-issuer" ]; then
    source .env-issuer
fi

# Verificar servicios de infraestructura
echo "🏗️ Servicios de Infraestructura:"

# Redis
echo ""
echo "🔍 Redis:"
if redis-cli ping > /dev/null 2>&1; then
    echo -e "  ${GREEN} Estado${NC}: Funcionando"
    local redis_info=$(redis-cli info server 2>/dev/null | grep -E "redis_version|uptime_in_seconds")
    if [ -n "$redis_info" ]; then
        echo "$redis_info" | while read line; do
            echo "  📊 $line"
        done
    fi
else
    echo -e "  ${RED}❌ Estado${NC}: No disponible"
fi

# PostgreSQL
echo ""
echo "🔍 PostgreSQL:"
if [ -n "$ISSUER_DATABASE_URL" ]; then
    # Parsear URL para extraer componentes
    db_url_no_proto=${ISSUER_DATABASE_URL#postgres://}
    db_creds_host=${db_url_no_proto%/*}
    
    if [[ $db_creds_host == *"@"* ]]; then
        db_creds=${db_creds_host%@*}
        db_host=${db_creds_host#*@}
        db_user=${db_creds%:*}
        db_password=${db_creds#*:}
        
        if PGPASSWORD="$db_password" psql -h "${db_host%:*}" -U "$db_user" -d "${db_url_no_proto##*/}" -c "SELECT version();" > /dev/null 2>&1; then
            echo -e "  ${GREEN} Estado${NC}: Conectado"
            
            # Mostrar información de la base de datos
            local table_count=$(PGPASSWORD="$db_password" psql -h "${db_host%:*}" -U "$db_user" -d "${db_url_no_proto##*/}" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null | tr -d ' ')
            if [ -n "$table_count" ]; then
                echo "  📊 Tablas: $table_count"
            fi
        else
            echo -e "  ${RED}❌ Estado${NC}: No se puede conectar"
        fi
    fi
else
    echo -e "  ${YELLOW}⚠️ Estado${NC}: URL no configurada"
fi

# Vault
echo ""
echo "🔍 Vault:"
if [ -n "$ISSUER_KEY_STORE_ADDRESS" ]; then
    if curl -s "$ISSUER_KEY_STORE_ADDRESS/v1/sys/health" > /dev/null 2>&1; then
        echo -e "  ${GREEN} Estado${NC}: Disponible"
        
        # Verificar si está sellado
        export VAULT_ADDR="$ISSUER_KEY_STORE_ADDRESS"
        if [ -n "$ISSUER_KEY_STORE_TOKEN" ]; then
            export VAULT_TOKEN="$ISSUER_KEY_STORE_TOKEN"
            
            if vault status 2>/dev/null | grep -q "Sealed.*false"; then
                echo -e "  ${GREEN} Sellado${NC}: No (disponible)"
            else
                echo -e "  ${YELLOW}⚠️ Sellado${NC}: Sí (requiere unseal)"
            fi
        fi
    else
        echo -e "  ${RED}❌ Estado${NC}: No disponible"
    fi
else
    echo -e "  ${YELLOW}⚠️ Estado${NC}: Dirección no configurada"
fi

# Verificar servicios principales
echo ""
echo " Servicios Principales:"

check_service_status "api" "API Principal" "${ISSUER_SERVER_PORT:-3001}"
check_service_status "notifications" "Servicio de Notificaciones"
check_service_status "publisher" "Publisher de Estados"

# Verificar conectividad externa
echo ""
echo " Conectividad Externa:"

# Verificar RPC blockchain
echo ""
echo "🔍 Blockchain RPC:"
if [ -n "$ISSUER_ETHEREUM_URL" ]; then
    if curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
        "$ISSUER_ETHEREUM_URL" | grep -q '"result"'; then
        echo -e "  ${GREEN} Estado${NC}: RPC responde"
        
        # Obtener Chain ID
        local chain_id=$(curl -s -X POST -H "Content-Type: application/json" \
            --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
            "$ISSUER_ETHEREUM_URL" | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
        
        if [ -n "$chain_id" ]; then
            local chain_id_decimal=$((16#${chain_id#0x}))
            echo "  📊 Chain ID: $chain_id ($chain_id_decimal)"
        fi
    else
        echo -e "  ${RED}❌ Estado${NC}: RPC no responde"
    fi
else
    echo -e "  ${YELLOW}⚠️ Estado${NC}: URL no configurada"
fi

# Resumen final
echo ""
echo "📋 Resumen:"

# Contar servicios funcionando
local running_services=0
local total_services=3

for service in api notifications publisher; do
    if [ -f "$PID_DIR/$service.pid" ]; then
        local pid=$(cat "$PID_DIR/$service.pid")
        if kill -0 "$pid" 2>/dev/null; then
            ((running_services++))
        fi
    fi
done

if [ $running_services -eq $total_services ]; then
    echo -e "  ${GREEN} Estado General${NC}: Todos los servicios funcionando ($running_services/$total_services)"
elif [ $running_services -gt 0 ]; then
    echo -e "  ${YELLOW}⚠️ Estado General${NC}: Parcialmente funcionando ($running_services/$total_services)"
else
    echo -e "  ${RED}❌ Estado General${NC}: No hay servicios ejecutándose ($running_services/$total_services)"
fi

# Información útil
echo ""
echo " Comandos útiles:"
echo "  ./start-all.sh    - Iniciar todos los servicios"
echo "  ./stop-all.sh     - Detener todos los servicios"
echo "  tail -f logs/api.log - Ver logs de API en tiempo real"
echo "  ./validate-config.sh - Validar configuración"
EOF

chmod +x status.sh
```

---

##  Verificación y Testing

### Paso 1: Script de Testing Básico

```bash
cat > test-issuer-node.sh << 'EOF'
#!/bin/bash

echo " Testing Privado ID Issuer-Node"
echo "================================="

# Configuración de testing
API_URL="${ISSUER_SERVER_URL:-http://localhost:3001}"
API_USER="${ISSUER_API_AUTH_USER:-user-issuer}"
API_PASS="${ISSUER_API_AUTH_PASSWORD:-password-issuer}"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Contador de tests
test_count=0
passed_tests=0

# Función para ejecutar test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_pattern="$3"
    
    ((test_count++))
    echo ""
    echo "Test $test_count: $test_name"
    echo "$(printf '%.0s-' {1..40})"
    
    # Ejecutar comando y capturar output
    local output
    output=$(eval "$test_command" 2>&1)
    local exit_code=$?
    
    # Verificar resultado
    if [ $exit_code -eq 0 ] && ([ -z "$expected_pattern" ] || echo "$output" | grep -q "$expected_pattern"); then
        echo -e "${GREEN} PASÓ${NC}"
        ((passed_tests++))
        
        # Mostrar output relevante si es corto
        if [ ${#output} -lt 200 ] && [ -n "$output" ]; then
            echo "Output: $output"
        fi
    else
        echo -e "${RED}❌ FALLÓ${NC}"
        echo "Exit code: $exit_code"
        echo "Output: $output"
        
        # Mostrar expected pattern si se especificó
        if [ -n "$expected_pattern" ]; then
            echo "Esperado: Que contenga '$expected_pattern'"
        fi
    fi
}

# Tests de infraestructura
echo "🏗️ Tests de Infraestructura"

run_test "Redis conectividad" \
    "redis-cli ping" \
    "PONG"

run_test "PostgreSQL conectividad" \
    "PGPASSWORD=issuernode_password psql -h localhost -U issuernode -d issuernode_db -c 'SELECT 1;'" \
    "1 row"

run_test "Vault disponibilidad" \
    "curl -s $ISSUER_KEY_STORE_ADDRESS/v1/sys/health" \
    "initialized"

# Tests de servicios
echo ""
echo " Tests de Servicios"

run_test "API Health Check" \
    "curl -s $API_URL/health" \
    ""

run_test "API Status con autenticación" \
    "curl -s -u $API_USER:$API_PASS $API_URL/status" \
    ""

run_test "API OpenAPI docs" \
    "curl -s $API_URL/api/docs" \
    "swagger"

# Tests de funcionalidad básica
echo ""
echo "⚙️ Tests de Funcionalidad"

run_test "Crear identidad de prueba" \
    "curl -s -X POST -u $API_USER:$API_PASS -H 'Content-Type: application/json' $API_URL/api/v1/identities -d '{\"didMetadata\":{\"method\":\"polygonid\",\"blockchain\":\"polygon\",\"network\":\"amoy\"}}'" \
    "identifier"

# Tests de blockchain
echo ""
echo "⛓️ Tests de Blockchain"

run_test "RPC Chain ID" \
    "curl -s -X POST -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"method\":\"eth_chainId\",\"params\":[],\"id\":1}' $ISSUER_ETHEREUM_URL" \
    "0x13882"

run_test "RPC Block Number" \
    "curl -s -X POST -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}' $ISSUER_ETHEREUM_URL" \
    "result"

# Tests de carga ligera
echo ""
echo "🚀 Tests de Carga Básica"

run_test "10 requests concurrentes al health" \
    "for i in {1..10}; do curl -s $API_URL/health & done; wait" \
    ""

run_test "API responde bajo carga" \
    "curl -s $API_URL/health" \
    ""

# Resumen
echo ""
echo "📊 Resumen de Tests"
echo "=================="

if [ $passed_tests -eq $test_count ]; then
    echo -e "${GREEN}🎉 Todos los tests pasaron: $passed_tests/$test_count${NC}"
    echo ""
    echo "✅ El sistema está funcionando correctamente"
    exit 0
elif [ $passed_tests -gt $((test_count / 2)) ]; then
    echo -e "${YELLOW}⚠️ Tests parcialmente exitosos: $passed_tests/$test_count${NC}"
    echo ""
    echo "🔧 Algunos componentes pueden necesitar atención"
    exit 1
else
    echo -e "${RED}❌ Muchos tests fallaron: $passed_tests/$test_count${NC}"
    echo ""
    echo "🚨 El sistema requiere corrección antes de usar en producción"
    exit 2
fi
EOF

chmod +x test-issuer-node.sh
```

### Paso 2: Script de Benchmark y Performance

```bash
cat > benchmark.sh << 'EOF'
#!/bin/bash

echo "📊 Benchmark del Privado ID Issuer-Node"
echo "======================================="

API_URL="${ISSUER_SERVER_URL:-http://localhost:3001}"
API_USER="${ISSUER_API_AUTH_USER:-user-issuer}"
API_PASS="${ISSUER_API_AUTH_PASSWORD:-password-issuer}"

# Verificar que curl esté disponible con timing
if ! command -v curl &> /dev/null; then
    echo "❌ curl no está instalado"
    exit 1
fi

# Función para medir tiempo de respuesta
measure_response_time() {
    local url="$1"
    local description="$2"
    local auth="$3"
    
    echo ""
    echo "🔍 $description"
    echo "URL: $url"
    
    # Hacer múltiples requests y calcular estadísticas
    local total_time=0
    local successful_requests=0
    local failed_requests=0
    local min_time=999999
    local max_time=0
    
    for i in {1..10}; do
        local start_time=$(date +%s.%3N)
        
        if [ -n "$auth" ]; then
            local response=$(curl -s -w "%{http_code}" -u "$auth" "$url")
        else
            local response=$(curl -s -w "%{http_code}" "$url")
        fi
        
        local end_time=$(date +%s.%3N)
        local request_time=$(echo "$end_time - $start_time" | bc -l)
        
        # Verificar código de respuesta
        local http_code="${response: -3}"
        
        if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
            ((successful_requests++))
            total_time=$(echo "$total_time + $request_time" | bc -l)
            
            # Actualizar min/max
            if (( $(echo "$request_time < $min_time" | bc -l) )); then
                min_time=$request_time
            fi
            
            if (( $(echo "$request_time > $max_time" | bc -l) )); then
                max_time=$request_time
            fi
        else
            ((failed_requests++))
            echo "  ⚠️ Request $i falló con código: $http_code"
        fi
        
        # Pausa pequeña entre requests
        sleep 0.1
    done
    
    if [ $successful_requests -gt 0 ]; then
        local avg_time=$(echo "scale=3; $total_time / $successful_requests" | bc -l)
        
        echo "  ✅ Requests exitosos: $successful_requests/10"
        echo "  📊 Tiempo promedio: ${avg_time}s"
        echo "  🚀 Tiempo mínimo: ${min_time}s"
        echo "  🐌 Tiempo máximo: ${max_time}s"
        
        if [ $failed_requests -gt 0 ]; then
            echo "  ❌ Requests fallidos: $failed_requests/10"
        fi
    else
        echo "  ❌ Todos los requests fallaron"
    fi
}

# Tests de rendimiento
echo "🚀 Midiendo rendimiento de endpoints..."

measure_response_time "$API_URL/health" "Health Check" ""

measure_response_time "$API_URL/status" "Status con autenticación" "$API_USER:$API_PASS"

measure_response_time "$API_URL/api/docs" "Documentación API" ""

# Test de carga más pesado
echo ""
echo "💪 Test de carga pesada (50 requests concurrentes)..."

local concurrent_start=$(date +%s.%3N)

# Ejecutar 50 requests en paralelo
for i in {1..50}; do
    curl -s "$API_URL/health" > /dev/null &
done

# Esperar que terminen todos
wait

local concurrent_end=$(date +%s.%3N)
local concurrent_total=$(echo "$concurrent_end - $concurrent_start" | bc -l)

echo "              db_password=${db_creds#*:}
            
            # Test de conexión usando psql
            if PGPASSWORD="$db_password" psql -h "${db_host%:*}" -p "${db_host#*:}" -U "$db_user" -d "$db_name" -c "SELECT 1;" > /dev/null 2>&1; then
                show_status "ok" "Conexión a PostgreSQL exitosa"
            else
                show_status "error" "No se puede conectar a PostgreSQL"
            fi
        else
            show_status "warn" "No se pudo parsear la URL de la base de datos para testing"
        fi
    else
        show_status "error" "URL de base de datos no es PostgreSQL válida"
    fi
else
    show_status "error" "ISSUER_DATABASE_URL no definido"
fi

echo ""
echo "💾 Validando configuración de cache (Redis)..."

if [ -n "$ISSUER_CACHE_URL" ]; then
    show_status "ok" "Cache URL: $ISSUER_CACHE_URL"
    
    # Test de conectividad a Redis
    echo "  🧪 Probando conexión a Redis..."
    if redis-cli -u "$ISSUER_CACHE_URL" ping > /dev/null 2>&1; then
        show_status "ok" "Conexión a Redis exitosa"
    else
        show_status "error" "No se puede conectar a Redis"
    fi
else
    show_status "error" "ISSUER_CACHE_URL no definido"
fi

echo ""
echo "🔐 Validando configuración KMS (Vault)..."

if [ -n "$ISSUER_KEY_STORE_ADDRESS" ]; then
    show_status "ok" "Vault Address: $ISSUER_KEY_STORE_ADDRESS"
    
    # Test de conectividad a Vault
    echo "  🧪 Probando conexión a Vault..."
    if curl -s "$ISSUER_KEY_STORE_ADDRESS/v1/sys/health" > /dev/null 2>&1; then
        show_status "ok" "Vault está accesible"
        
        # Verificar autenticación si hay token
        if [ -n "$ISSUER_KEY_STORE_TOKEN" ]; then
            export VAULT_ADDR="$ISSUER_KEY_STORE_ADDRESS"
            export VAULT_TOKEN="$ISSUER_KEY_STORE_TOKEN"
            
            if vault token lookup > /dev/null 2>&1; then
                show_status "ok" "Token de Vault válido"
            else
                show_status "warn" "Token de Vault inválido o Vault sellado"
            fi
        else
            show_status "warn" "Token de Vault no definido"
        fi
    else
        show_status "error" "No se puede conectar a Vault"
    fi
else
    show_status "error" "ISSUER_KEY_STORE_ADDRESS no definido"
fi

echo ""
echo "📁 Validando archivos y directorios..."

# Verificar archivos de configuración
if [ -f "resolvers_settings.yaml" ]; then
    show_status "ok" "resolvers_settings.yaml encontrado"
else
    show_status "warn" "resolvers_settings.yaml no encontrado"
fi

# Verificar binarios
binaries=("issuer-api" "notifications" "pending-publisher" "migrate")
for binary in "${binaries[@]}"; do
    if [ -f "./$binary" ] && [ -x "./$binary" ]; then
        show_status "ok" "Binario $binary encontrado y ejecutable"
    else
        show_status "error" "Binario $binary no encontrado o no ejecutable"
    fi
done

# Verificar directorio de circuitos si está definido
if [ -n "$ISSUER_CIRCUIT_PATH" ]; then
    if [ -d "$ISSUER_CIRCUIT_PATH" ]; then
        show_status "ok" "Directorio de circuitos encontrado"
        
        # Contar archivos de circuitos
        circuit_count=$(find "$ISSUER_CIRCUIT_PATH" -name "*.wasm" -o -name "*.zkey" | wc -l)
        if [ $circuit_count -gt 0 ]; then
            show_status "ok" "Encontrados $circuit_count archivos de circuitos"
        else
            show_status "warn" "No se encontraron archivos de circuitos (.wasm/.zkey)"
        fi
    else
        show_status "warn" "Directorio de circuitos no existe: $ISSUER_CIRCUIT_PATH"
    fi
fi

echo ""
echo "📊 Resumen de validación:"

# Contar errores y warnings
error_count=$(grep -c "❌" /tmp/validation_output 2>/dev/null || echo 0)
warn_count=$(grep -c "⚠️" /tmp/validation_output 2>/dev/null || echo 0)

if [ $error_count -eq 0 ]; then
    if [ $warn_count -eq 0 ]; then
        echo -e "${GREEN}🎉 Configuración completamente válida${NC}"
    else
        echo -e "${YELLOW}✅ Configuración válida con $warn_count advertencias${NC}"
    fi
    echo ""
    echo "🚀 Sistema listo para ejecutar:"
    echo "  1. ./migrate up"
    echo "  2. ./start-all.sh"
else
    echo -e "${RED}❌ Configuración inválida: $error_count errores, $warn_count advertencias${NC}"
    echo ""
    echo "🔧 Corrige los errores antes de continuar"
fi
EOF

chmod +x validate-config.sh
```

### Paso 4: Actualización del Token de Vault

Después de configurar Vault, necesitas actualizar el token en tu archivo de configuración:

```bash
# Obtener el token de Vault configurado anteriormente
if [ -f "$HOME/vault-config/root-token" ]; then
    VAULT_TOKEN=$(cat "$HOME/vault-config/root-token")
    
    # Actualizar el archivo .env-issuer con el token real
    sed -i "s/TU_VAULT_ROOT_TOKEN_AQUI/$VAULT_TOKEN/g" .env-issuer
    
    echo "✅ Token de Vault actualizado en .env-issuer"
else
    echo "❌ Token de Vault no encontrado. Ejecuta primero la configuración de Vault"
fi
```

---

## 🚀 Inicialización y Migración

### Comprensión del Sistema de Migraciones

Las migraciones son scripts SQL que crean y modifican la estructura de la base de datos. El issuer-node utiliza una herramienta de migración personalizada que:

1. **Rastrea versiones**: Mantiene registro de qué migraciones se han aplicado
2. **Aplica cambios incrementales**: Solo ejecuta migraciones nuevas
3. **Soporte rollback**: Permite revertir cambios si es necesario
4. **Validación**: Verifica integridad antes de aplicar cambios

### Paso 1: Preparación del Entorno

```bash
cd $HOME/privado-id-development/issuer-node

# Verificar que todos los servicios están funcionando
echo "🔍 Verificando servicios previo a migración..."

# PostgreSQL
if PGPASSWORD=issuernode_password psql -h localhost -U issuernode -d issuernode_db -c "SELECT version();" > /dev/null 2>&1; then
    echo "✅ PostgreSQL funcionando"
else
    echo "❌ PostgreSQL no funciona"
    exit 1
fi

# Redis
if redis-cli ping > /dev/null 2>&1; then
    echo "✅ Redis funcionando"
else
    echo "❌ Redis no funciona"
    exit 1
fi

# Vault
export VAULT_ADDR='http://127.0.0.1:8200'
if [ -f "$HOME/vault-config/root-token" ]; then
    export VAULT_TOKEN=$(cat "$HOME/vault-config/root-token")
    
    if vault token lookup > /dev/null 2>&1; then
        echo "✅ Vault funcionando"
    else
        echo "❌ Vault no funciona o está sellado"
        exit 1
    fi
else
    echo "❌ Token de Vault no encontrado"
    exit 1
fi
```

### Paso 2: Validación Pre-Migración

```bash
# Ejecutar validación completa de configuración
./validate-config.sh

# Verificar que el binario migrate funciona
echo "🧪 Probando herramienta de migración..."
if ./migrate --help > /dev/null 2>&1; then
    echo "✅ Herramienta migrate funcional"
else
    echo "❌ Error con herramienta migrate"
    echo "🔧 Recompila con: go build -o migrate ./cmd/migrate"
    exit 1
fi
```

### Paso 3: Ejecución de Migraciones

```bash
cat > run-migrations.sh << 'EOF'
#!/bin/bash

echo "🗄️ Ejecutando migraciones de base de datos..."

# Cargar configuración
if [ -f ".env-issuer" ]; then
    source .env-issuer
else
    echo "❌ Archivo .env-issuer no encontrado"
    exit 1
fi

# Verificar configuración crítica
if [ -z "$ISSUER_DATABASE_URL" ]; then
    echo "❌ ISSUER_DATABASE_URL no definido"
    exit 1
fi

echo "📊 Información de migración:"
echo "  Base de datos: $ISSUER_DATABASE_URL"
echo "  Directorio de migraciones: ./migrations"
echo ""

# Verificar directorio de migraciones
if [ ! -d "./migrations" ]; then
    echo "❌ Directorio ./migrations no encontrado"
    echo "💡 Verifica que estás en el directorio raíz del proyecto"
    exit 1
fi

# Mostrar migraciones disponibles
echo "📋 Migraciones disponibles:"
ls -1 ./migrations/*.sql 2>/dev/null | head -10

echo ""
echo "🚀 Ejecutando migraciones..."

# Exportar variables para que migrate las vea
export ISSUER_DATABASE_URL

# Ejecutar migraciones con output detallado
./migrate up

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Migraciones ejecutadas exitosamente"
    
    # Verificar tablas creadas
    echo ""
    echo "📊 Verificando estructura de base de datos..."
    
    # Extraer componentes de la URL para psql
    db_url_no_proto=${ISSUER_DATABASE_URL#postgres://}
    db_creds_host=${db_url_no_proto%/*}
    db_name=${db_url_no_proto##*/}
    db_name=${db_name%\?*}
    
    if [[ $db_creds_host == *"@"* ]]; then
        db_creds=${db_creds_host%@*}
        db_host=${db_creds_host#*@}
        db_user=${db_creds%:*}
        db_password=${db_creds#*:}
        
        echo "Tablas principales creadas:"
        PGPASSWORD="$db_password" psql -h "${db_host%:*}" -p "${db_host#*:}" -U "$db_user" -d "$db_name" -c "
            SELECT schemaname, tablename, tableowner 
            FROM pg_tables 
            WHERE schemaname = 'public' 
            ORDER BY tablename;" 2>/dev/null || echo "No se pudo verificar tablas"
        
        echo ""
        echo "Estado de migraciones:"
        PGPASSWORD="$db_password" psql -h "${db_host%:*}" -p "${db_host#*:}" -U "$db_user" -d "$db_name" -c "
            SELECT version, dirty, applied_at 
            FROM schema_migrations 
            ORDER BY version DESC 
            LIMIT 5;" 2>/dev/null || echo "Tabla schema_migrations no encontrada"
    fi
    
else
    echo ""
    echo "❌ Error durante las migraciones"
    echo "🔍 Revisa los logs arriba para detalles del error"
    
    # Mostrar información adicional para debug
    echo ""
    echo "🔍 Información de debug:"
    echo "  Variables de entorno:"
    echo "    ISSUER_DATABASE_URL: ${ISSUER_DATABASE_URL:0:30}..."
    echo "  Binario migrate:"
    ls -la ./migrate
    echo "  Directorio migraciones:"
    ls -la ./migrations/ | head -5
    
    exit 1
fi
EOF

chmod +x run-migrations.sh
./run-migrations.sh
```

### Paso 4: Configuración Inicial del Vault para Claves

Después de las migraciones, necesitamos configurar las claves criptográficas en Vault:

```bash
cat > setup-vault-keys.sh << 'EOF'
#!/bin/bash

echo "🔐 Configurando claves criptográficas en Vault..."

# Configurar variables de Vault
export VAULT_ADDR='http://127.0.0.1:8200'

# Cargar token si existe
if [ -f "$HOME/vault-config/root-token" ]; then
    export VAULT_TOKEN=$(cat "$HOME/vault-config/root-token")
else
    echo "❌ Token de Vault no encontrado"
    echo "💡 Ejecuta primero la configuración de Vault"
    exit 1
fi

# Verificar autenticación
echo "🔑 Verificando autenticación con Vault..."
if vault token lookup > /dev/null 2>&1; then
    echo "✅ Autenticación exitosa"
else
    echo "❌ Error de autenticación con Vault"
    exit 1
fi

# Verificar que el secret engine está configurado
echo "📦 Verificando secret engine..."
if vault secrets list | grep -q "secret/"; then
    echo "✅ Secret engine KV disponible"
else
    echo "⚙️ Configurando secret engine KV..."
    vault secrets enable -path=secret -version=2 kv
fi

echo ""
echo "🔑 Configuración de claves Ethereum..."

# Solicitar clave privada Ethereum
echo "Para el issuer-node necesitas una clave privada Ethereum que:"
echo "  1. Tenga fondos MATIC en Polygon Amoy (testnet)"
echo "  2. Se use para publicar estados en blockchain"
echo ""
echo "Puedes:"
echo "  A) Usar una clave existente de tu wallet (MetaMask, etc.)"
echo "  B) Generar una nueva clave"
echo ""

read -p "¿Quieres (G)enerar una nueva clave o (I)ngresar una existente? [G/i]: " choice

if [[ $choice =~ ^[Ii]$ ]]; then
    # Ingresar clave existente
    echo ""
    echo "⚠️  Ingresa tu clave privada Ethereum (64 caracteres hex, sin 0x):"
    echo "Ejemplo: a1b2c3d4e5f6789012345678901234567890abcdef..."
    read -s -p "Clave privada: " eth_private_key
    echo ""
    
    # Validar formato
    if [[ ! $eth_private_key =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "❌ Formato de clave inválido. Debe ser 64 caracteres hexadecimales"
        exit 1
    fi
    
else
    # Generar nueva clave
    echo "🎲 Generando nueva clave privada Ethereum..."
    
    # Generar clave aleatoria usando openssl
    eth_private_key=$(openssl rand -hex 32)
    
    echo "✅ Clave generada exitosamente"
    echo ""
    echo "⚠️  IMPORTANTE: Guarda esta información en lugar seguro"
    echo "==============================================="
    echo "Clave privada: $eth_private_key"
    
    # Calcular dirección pública (simplificado)
    echo "💡 Para obtener la dirección pública e importar a MetaMask:"
    echo "  1. Abre MetaMask -> Configuración -> Avanzado -> Importar cuenta"
    echo "  2. Pega la clave privada: $eth_private_key"
    echo "  3. Obtén MATIC de testnet en: https://faucet.polygon.technology/"
    echo "==============================================="
    echo ""
    
    read -p "¿Has guardado la clave privada en lugar seguro? [y/N]: " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        echo "⚠️ Guarda la clave privada antes de continuar"
        exit 1
    fi
fi

# Guardar clave en Vault
echo "💾 Guardando clave privada en Vault..."

# Usar el path definido en la configuración
vault kv put secret/pbkey privateKey="$eth_private_key"

if [ $? -eq 0 ]; then
    echo "✅ Clave privada guardada exitosamente en Vault"
    
    # Verificar que se guardó correctamente
    echo "🧪 Verificando almacenamiento..."
    if vault kv get secret/pbkey > /dev/null 2>&1; then
        echo "✅ Clave verificada en Vault"
        
        # Mostrar metadata (sin mostrar la clave)
        echo ""
        echo "📊 Información de la clave guardada:"
        vault kv metadata get secret/pbkey
        
    else
        echo "❌ Error al verificar la clave en Vault"
        exit 1
    fi
else
    echo "❌ Error al guardar clave en Vault"
    exit 1
fi

echo ""
echo "🎉 Configuración de claves completada"
echo ""
echo "📝 Próximos pasos:"
echo "  1. Asegúrate de que la dirección Ethereum tenga fondos MATIC en Amoy"
echo "  2. Ejecuta: ./start-all.sh para iniciar todos los servicios"

# Limpiar variable con clave privada
unset eth_private_key
EOF

chmod +x setup-vault-keys.sh
```

### Paso 5: Script de Inicialización Completa

```bash
cat > initialize-all.sh << 'EOF'
#!/bin/bash

echo "🚀 Inicialización completa del Privado ID Issuer-Node"
echo "===================================================="

# Función para mostrar pasos
step_counter=1
show_step() {
    echo ""
    echo "📋 Paso $step_counter: $1"
    echo "$(printf '%.0s-' {1..50})"
    ((step_counter++))
}

# Verificar directorio
if [ ! -f "go.mod" ] || ! grep -q "github.com/polygonid/sh-id-platform" go.mod 2>/dev/null; then
    echo "❌ Error: No estás en el directorio raíz del proyecto issuer-node"
    echo "💡 Ejecuta: cd \$HOME/privado-id-development/issuer-node"
    exit 1
fi

show_step "Verificar servicios de infraestructura"

# Verificar Redis
if ! redis-cli ping > /dev/null 2>&1; then
    echo "⚙️ Iniciando Redis..."
    $HOME/redis-control.sh start || {
        echo "❌ Error al iniciar Redis"
        exit 1
    }
fi

# Verificar PostgreSQL
if ! PGPASSWORD=issuernode_password psql -h localhost -U issuernode -d issuernode_db -c "SELECT 1;" > /dev/null 2>&1; then
    echo "❌ PostgreSQL no está configurado correctamente"
    echo "💡 Ejecuta el script de configuración de PostgreSQL"
    exit 1
fi

# Verificar Vault
export VAULT_ADDR='http://127.0.0.1:8200'
if ! curl -s "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; then
    echo "⚙️ Iniciando Vault..."
    $HOME/vault-control.sh start || {
        echo "❌ Error al iniciar Vault"
        exit 1
    }
    
    # Desbloquear si es necesario
    $HOME/vault-control.sh unseal
fi

# Autenticar con Vault
if [ -f "$HOME/vault-config/root-token" ]; then
    export VAULT_TOKEN=$(cat "$HOME/vault-config/root-token")
    
    if ! vault token lookup > /dev/null 2>&1; then
        echo "⚙️ Autenticando con Vault..."
        $HOME/vault-control.sh login
    fi
fi

show_step "Validar configuración"
./validate-config.sh

show_step "Compilar binarios"
./compile-all.sh

show_step "Ejecutar migraciones de base de datos"
./run-migrations.sh

show_step "Configurar claves criptográficas"
./setup-vault-keys.sh

show_step "Verificación final"

echo "🧪 Probando que todos los componentes están listos..."

# Verificar binarios
for binary in issuer-api notifications pending-publisher; do
    if [ -x "./$binary" ]; then
        echo "  ✅ $binary está compilado y ejecutable"
    else
        echo "  ❌ $binary no está disponible"
        exit 1
    fi
done

# Verificar configuración cargada
source .env-issuer
if [ -n "$ISSUER_CACHE_URL" ] && [ -n "$ISSUER_DATABASE_URL" ] && [ -n "$ISSUER_KEY_STORE_ADDRESS" ]; then
    echo "  ✅ Variables de configuración cargadas"
else
    echo "  ❌ Configuración incompleta"
    exit 1
fi

# Verificar clave en Vault
if vault kv get secret/pbkey > /dev/null 2>&1; then
    echo "  ✅ Clave privada configurada en Vault"
else
    echo "  ❌ Clave privada no encontrada en Vault"
    exit 1
fi

echo ""
echo "🎉 ¡Inicialización completada exitosamente!"
echo ""
echo "🚀 Para iniciar el issuer-node:"
echo "  ./start-all.sh"
echo ""
echo "📱 Interfaces disponibles:"
echo "  - API REST: http://localhost:3001"
echo "  - Documentación: http://localhost:3001/api/docs"
echo "  - Vault UI: http://127.0.0.1:8200"
echo ""
echo "🔑 Credenciales por defecto:"
echo "  - API: user-issuer / password-issuer"
echo "  - Vault: Token en $HOME/vault-config/root-token"
EOF

chmod +x initialize-all.sh
```

---

## 🚀 Ejecución del Sistema

### Comprensión de la Arquitectura de Servicios

El issuer-node consta de tres servicios principales que deben ejecutarse concurrentemente:

1. **issuer-api**: Servicio principal HTTP/REST
2. **notifications**: Procesador de notificaciones asíncronas  
3. **pending-publisher**: Publicador de estados blockchain

### Paso 1: Scripts de Inicio Individual

```bash
# Script para API principal
cat > start-api.sh << 'EOF'
#!/bin/bash

echo "🚀 Iniciando Issuer API..."

# Cambiar al directorio correcto
cd "$(dirname "$0")"

# Verificar binario
if [ ! -x "./issuer-api" ]; then
    echo "❌ Binario issuer-api no encontrado o no ejecutable"
    echo "💡 Ejecuta: ./compile-all.sh"
    exit 1
fi

# Verificar configuración
if [ ! -f ".env-issuer" ]; then
    echo "❌ Archivo .env-issuer no encontrado"
    echo "💡 Ejecuta: ./initialize-all.sh"
    exit 1
fi

# Cargar configuración
echo "⚙️ Cargando configuración..."
source .env-issuer

# Verificar variables críticas
critical_vars=("ISSUER_DATABASE_URL" "ISSUER_CACHE_URL" "ISSUER_KEY_STORE_ADDRESS")
for var in "${critical_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "❌ Variable crítica no definida: $var"
        echo "💡 Revisa tu archivo .env-issuer"
        exit 1
    fi
done

# Crear directorio de logs si no existe
mkdir -p logs

# Función para manejar señales de interrupción
cleanup() {
    echo ""
    echo "🛑 Deteniendo Issuer API..."
    exit 0
}

trap cleanup SIGINT SIGTERM

# Mostrar información de inicio
echo "📊 Configuración:"
echo "  Puerto: $ISSUER_SERVER_PORT"
echo "  Base de datos: ${ISSUER_DATABASE_URL%\?*}"
echo "  Cache: $ISSUER_CACHE_URL"
echo "  Vault: $ISSUER_KEY_STORE_ADDRESS"
echo "  Log level: $ISSUER_LOG_LEVEL"
echo ""

# Verificar conectividad rápida antes de iniciar
echo "🔍 Verificando servicios..."

# Redis
if ! redis-cli -u "$ISSUER_CACHE_URL" ping > /dev/null 2>&1; then
    echo "❌ No se puede conectar a Redis"
    exit 1
fi

# Vault
if ! curl -s "$ISSUER_KEY_STORE_ADDRESS/v1/sys/health" > /dev/null 2>&1; then
    echo "❌ No se puede conectar a Vault"
    exit 1
fi

echo "✅ Servicios verificados"
echo ""

# Iniciar API principal
echo "🌟 Iniciando servidor en puerto $ISSUER_SERVER_PORT..."
echo "📝 Logs guardándose en logs/api.log"
echo "🔗 API disponible en: $ISSUER_SERVER_URL"
echo ""
echo "Presiona Ctrl+C para detener..."

# Ejecutar con logs tanto en pantalla como en archivo
./issuer-api 2>&1 | tee logs/api.log
EOF

# Script para servicio de notificaciones
cat > start-notifications.sh << 'EOF'
#!/bin/bash

echo "📢 Iniciando Servicio de Notificaciones..."

cd "$(dirname "$0")"

if [ ! -x "./notifications" ]; then
    echo "❌ Binario notifications no encontrado"
    exit 1
fi

if [ ! -f ".env-issuer" ]; then
    echo "❌ Archivo .env-issuer no encontrado"
    exit 1
fi

source .env-issuer
mkdir -p logs

cleanup() {
    echo ""
    echo "🛑 Deteniendo servicio de notificaciones..."
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "📊 Configuración de notificaciones:"
echo "  Base de datos: ${ISSUER_DATABASE_URL%\?*}"
echo "  Cache: $ISSUER_CACHE_URL"
echo ""

echo "🔍 Verificando servicios..."
if ! redis-cli -u "$ISSUER_CACHE_URL" ping > /dev/null 2>&1; then
    echo "❌ Redis no disponible"
    exit 1
fi

echo "✅ Servicios verificados"
echo "🌟 Iniciando servicio de notificaciones..."
echo "📝 Logs en logs/notifications.log"
echo ""

./notifications 2>&1 | tee logs/notifications.log
EOF

# Script para servicio publisher
cat > start-publisher.sh << 'EOF'
#!/bin/bash

echo "🌐 Iniciando Publisher de Estados Blockchain..."

cd "$(dirname "$0")"

if [ ! -x "./pending-publisher" ]; then
    echo "❌ Binario pending-publisher no encontrado"
    exit 1
fi

if [ ! -f ".env-issuer" ]; then
    echo "❌ Archivo .env-issuer no encontrado"
    exit 1
fi

source .env-issuer
mkdir -p logs

cleanup() {
    echo ""
    echo "🛑 Deteniendo publisher..."
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "📊 Configuración del publisher:"
echo "  Blockchain: $ISSUER_ETHEREUM_URL"
echo "  Contrato: $ISSUER_ETHEREUM_CONTRACT_ADDRESS"  
echo "  Vault: $ISSUER_KEY_STORE_ADDRESS"
echo "  Frecuencia: $ISSUER_ONCHAIN_PUBLISH_STATE_FREQUENCY"
echo ""

echo "🔍 Verificando servicios..."

# Verificar RPC blockchain
if ! curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
    "$ISSUER_ETHEREUM_URL" | grep -q '"result"'; then
    echo "❌ RPC blockchain no responde"
    exit 1
fi

# Verificar Vault
if ! curl -s "$ISSUER_KEY_STORE_ADDRESS/v1/sys/health" > /dev/null 2>&1; then
    echo "❌ Vault no disponible"
    exit 1
fi

echo "✅ Servicios verificados"
echo "🌟 Iniciando publisher de estados..."
echo "📝 Logs en logs/publisher.log"
echo ""

./pending-publisher 2>&1 | tee logs/publisher.log
EOF

chmod +x start-api.sh start-notifications.sh start-publisher.sh
```

### Paso 2: Script de Inicio Completo

```bash
cat > start-all.sh << 'EOF'
#!/bin/bash

echo "🚀 Iniciando Privado ID Issuer-Node Completo"
echo "============================================="

# Configuración
LOG_DIR="logs"
PID_DIR="pids"

# Crear directorios necesarios
mkdir -p "$LOG_DIR" "$PID_DIR"

# Función para limpiar procesos al salir
cleanup() {
    echo ""
    echo "🛑 Deteniendo todos los servicios..."
    
    # Leer PIDs de archivos y matar procesos
    for service in api notifications publisher; do
        if [ -f "$PID_DIR/$service.pid" ]; then
            pi# Privado ID Issuer-Node - Instalación Nativa Completa (Sin Docker)

## 📖 Índice

- [Introducción Conceptual](#-introducción-conceptual)
- [¿Qué es Privado ID?](#-qué-es-privado-id)
- [Arquitectura del Sistema](#-arquitectura-del-sistema)
- [Prerrequisitos del Sistema](#-prerrequisitos-del-sistema)
- [Instalación de Dependencias](#-instalación-de-dependencias)
- [Configuración de Servicios](#-configuración-de-servicios)
- [Compilación del Issuer-Node](#-compilación-del-issuer-node)
- [Configuración de Variables](#-configuración-de-variables)
- [Inicialización y Migración](#-inicialización-y-migración)
- [Ejecución del Sistema](#-ejecución-del-sistema)
- [Verificación y Testing](#-verificación-y-testing)
- [Troubleshooting](#-troubleshooting)
- [Scripts de Automatización](#-scripts-de-automatización)
- [Mantenimiento](#-mantenimiento)
- [Seguridad y Consideraciones](#-seguridad-y-consideraciones)

---

## 🎯 Introducción Conceptual

### ¿Por qué esta guía?

El **Privado ID Issuer-Node** es oficialmente distribuido como contenedores Docker para simplificar el despliegue. Sin embargo, en ciertos entornos de desarrollo, testing o producción específicos, puede ser necesario ejecutar los componentes de forma nativa sin contenedores Docker.

Esta guía documenta el proceso completo para compilar, configurar y ejecutar todos los componentes del Issuer-Node directamente en el sistema operativo Linux, replicando la funcionalidad que normalmente proporciona Docker Compose.

### Diferencias vs Instalación Docker

| Aspecto | Docker (Oficial) | Instalación Nativa (Esta Guía) |
|---------|------------------|--------------------------------|
| **Complejidad** | Baja (1 comando) | Alta (múltiples pasos) |
| **Dependencias** | Auto-contenidas | Instalación manual requerida |
| **Aislamiento** | Contenedores separados | Procesos del sistema |
| **Persistencia** | Volúmenes Docker | Directorios del sistema |
| **Actualizaciones** | Pull de imágenes | Recompilación manual |
| **Soporte** | Oficial | Comunidad/Experimental |
| **Debugging** | Limitado | Acceso directo al código |

---

## 🏗️ ¿Qué es Privado ID?

### Definición Técnica

**Privado ID** (anteriormente Polygon ID) es una plataforma de identidad descentralizada que implementa el estándar **Self-Sovereign Identity (SSI)** utilizando **Zero-Knowledge Proofs (ZKPs)** para permitir verificación de identidad y credenciales sin revelar información privada.

### Componentes Principales

1. **Issuer-Node**: Servidor que emite credenciales verificables (VCs)
2. **Verifier**: Sistema que verifica credenciales sin acceder a datos privados
3. **Wallet**: Aplicación móvil/web que almacena credenciales del usuario
4. **Blockchain**: Polygon (Amoy testnet) para anclaje de estados criptográficos

### ¿Qué hace el Issuer-Node específicamente?

- **Emisión de Credenciales**: Genera credenciales digitales firmadas criptográficamente
- **Gestión de Identidades**: Crea y gestiona DIDs (Decentralized Identifiers)
- **Publicación de Estados**: Ancla hashes de estado en la blockchain Polygon
- **Gestión de Esquemas**: Define estructuras de datos para credenciales
- **APIs REST**: Proporciona endpoints para interactuar con el sistema
- **Interface Web**: UI para gestión visual de credenciales e identidades

---

## 🏛️ Arquitectura del Sistema

### Componentes de Software

```mermaid
graph TB
    A[issuer-api] --> B[PostgreSQL Database]
    A --> C[Redis Cache]
    A --> D[HashiCorp Vault]
    A --> E[Polygon Amoy RPC]
    
    F[notifications] --> B
    F --> C
    
    G[pending-publisher] --> B
    G --> D
    G --> E
    
    H[UI Frontend] --> A
    I[Mobile Wallet] --> A
```

### Descripción de Componentes

#### issuer-api (Componente Principal)
- **Función**: API REST principal que maneja todas las operaciones de emisión
- **Puerto**: 3001 (configurable)
- **Responsabilidades**:
  - Autenticación de usuarios de la API
  - CRUD de identidades y credenciales
  - Generación de pruebas criptográficas (ZK-SNARKs)
  - Interfaz con blockchain para publicar estados

#### notifications
- **Función**: Servicio de notificaciones asíncronas
- **Responsabilidades**:
  - Envío de webhooks a sistemas externos
  - Notificaciones push a wallets móviles
  - Logging de eventos del sistema

#### pending-publisher  
- **Función**: Publicador de estados en blockchain
- **Responsabilidades**:
  - Monitor de transacciones pendientes
  - Publicación automática de cambios de estado
  - Reintento de transacciones fallidas

### Servicios de Infraestructura

#### PostgreSQL (Base de Datos Principal)
- **Versión**: 14+
- **Función**: Almacenamiento persistente de:
  - Identidades (DIDs)
  - Credenciales emitidas
  - Conexiones usuario-emisor
  - Logs de transacciones
  - Metadatos de esquemas

#### Redis (Cache y Cola de Tareas)
- **Versión**: 6+  
- **Función**: 
  - Cache de consultas frecuentes
  - Sesiones de API
  - Cola de trabajos asíncronos
  - Rate limiting

#### HashiCorp Vault (Gestión de Claves)
- **Versión**: 1.15+
- **Función**: Almacenamiento seguro de:
  - Claves privadas BabyJubJub (para DIDs)
  - Claves privadas Ethereum (para transacciones)
  - Tokens de API externos
  - Certificados TLS

---

## 🖥️ Prerrequisitos del Sistema

### Sistema Operativo Soportado

- **Ubuntu 20.04 LTS** o superior
- **Debian 11** o superior  
- **CentOS 8** o superior
- **RHEL 8** o superior
- **Fedora 35** o superior
- **Arch Linux** (última versión estable)

**⚠️ Importante**: Windows no es compatible, ni siquiera con WSL (Windows Subsystem for Linux).

### Recursos Mínimos del Sistema

| Recurso | Desarrollo | Producción |
|---------|------------|------------|
| **CPU** | 2 cores | 4+ cores |
| **RAM** | 4 GB | 8+ GB |
| **Almacenamiento** | 10 GB | 50+ GB SSD |
| **Red** | Acceso a internet | Conexión estable + IP pública |

### Conexión Externa Requerida

- **RPC Polygon Amoy**: Para transacciones blockchain
- **IPFS Gateway**: Para almacenamiento de metadatos (opcional)
- **Faucet Amoy**: Para obtener MATIC de prueba
- **NPM/GitHub**: Para descargar dependencias

---

## 📦 Instalación de Dependencias

### Paso 1: Actualización del Sistema Base

```bash
# Ubuntu/Debian
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git build-essential

# CentOS/RHEL/Fedora  
sudo yum update -y
sudo yum groupinstall -y "Development Tools"
sudo yum install -y curl wget git

# Arch Linux
sudo pacman -Syu
sudo pacman -S base-devel git curl wget
```

### Paso 2: Instalación de Go 1.21+

#### ¿Por qué Go 1.21+?
El proyecto Issuer-Node utiliza características específicas de Go 1.21+, incluyendo:
- Nuevas características del compilador para optimización
- Módulos Go actualizados con dependencias específicas
- APIs de criptografía mejoradas

#### Instalación desde Binario Oficial (Recomendado)

```bash
# Cambiar al directorio temporal
cd /tmp

# Descargar Go 1.21.6 (versión estable probada)
wget https://golang.org/dl/go1.21.6.linux-amd64.tar.gz

# Verificar integridad (opcional pero recomendado)
echo "b928166de79db0a04a50e7b7e3e652b7a8b9c72c44fcbc62d16e32e8a8d6b34a go1.21.6.linux-amd64.tar.gz" | sha256sum -c

# Eliminar instalación anterior de Go (si existe)
sudo rm -rf /usr/local/go

# Extraer Go al directorio estándar
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz

# Configurar variables de entorno permanentes
cat >> ~/.bashrc << 'EOF'
# Go Programming Language
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export GOBIN=$GOPATH/bin
export PATH=$PATH:$GOBIN
EOF

# Aplicar cambios inmediatamente
source ~/.bashrc

# Crear directorio de trabajo Go
mkdir -p $HOME/go/{bin,src,pkg}
```

#### Verificación de la Instalación de Go

```bash
# Verificar versión de Go
go version
# Output esperado: go version go1.21.6 linux/amd64

# Verificar variables de entorno
go env GOPATH GOROOT
# GOPATH debería ser: /home/tu-usuario/go
# GOROOT debería ser: /usr/local/go

# Probar compilación básica
echo 'package main; import "fmt"; func main() { fmt.Println("Go funciona!") }' > /tmp/test.go
go run /tmp/test.go
# Output esperado: Go funciona!
```

### Paso 3: Instalación de Make y Herramientas de Compilación

```bash
# Ubuntu/Debian
sudo apt install -y make gcc g++ pkg-config libc6-dev

# CentOS/RHEL/Fedora
sudo yum install -y make gcc gcc-c++ pkgconfig glibc-devel

# Arch Linux  
sudo pacman -S make gcc pkgconf

# Verificar instalación
make --version
gcc --version
```

---

## 🗄️ Configuración de Servicios

### PostgreSQL - Base de Datos Principal

#### ¿Por qué PostgreSQL?
- **ACID Compliance**: Garantiza integridad de datos críticos
- **JSON Support**: Almacena metadatos de credenciales como JSON
- **Extensibilidad**: Soporte para tipos de datos personalizados
- **Performance**: Optimizado para consultas complejas

#### Instalación

```bash
# Ubuntu/Debian
sudo apt install -y postgresql postgresql-contrib postgresql-client-14

# CentOS/RHEL 8
sudo dnf install -y postgresql postgresql-server postgresql-contrib
sudo postgresql-setup --initdb

# Fedora
sudo dnf install -y postgresql postgresql-server postgresql-contrib
sudo postgresql-setup --initdb --unit postgresql

# Arch Linux
sudo pacman -S postgresql
sudo -u postgres initdb -D /var/lib/postgres/data
```

#### Configuración Inicial

```bash
# Iniciar servicio PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Verificar que el servicio está corriendo
sudo systemctl status postgresql
# Debería mostrar: Active: active (running)
```

#### Configuración de Usuario y Base de Datos

```bash
# Conectar como superusuario postgres
sudo -u postgres psql

# Dentro de la consola psql, ejecutar:
```

```sql
-- Crear usuario específico para el issuer-node
CREATE USER issuernode WITH PASSWORD 'issuernode_password';

-- Otorgar privilegios de creación de bases de datos
ALTER USER issuernode CREATEDB;

-- Crear base de datos principal
CREATE DATABASE issuernode_db OWNER issuernode;

-- Conectar a la nueva base de datos
\c issuernode_db

-- Otorgar todos los privilegios en la base de datos
GRANT ALL PRIVILEGES ON DATABASE issuernode_db TO issuernode;
GRANT ALL ON SCHEMA public TO issuernode;

-- Verificar la creación
\l
-- Debería mostrar issuernode_db con owner issuernode

-- Salir de psql
\q
```

#### Configuración de Autenticación

PostgreSQL por defecto usa autenticación "peer" que requiere que el usuario del sistema coincida con el usuario de la base de datos. Necesitamos cambiar esto a autenticación por contraseña.

```bash
# Encontrar archivo de configuración pg_hba.conf
sudo find /etc -name "pg_hba.conf" 2>/dev/null
# Ubicación común: /etc/postgresql/14/main/pg_hba.conf

# Hacer backup del archivo original
sudo cp /etc/postgresql/14/main/pg_hba.conf /etc/postgresql/14/main/pg_hba.conf.backup

# Editar configuración
sudo nano /etc/postgresql/14/main/pg_hba.conf
```

**Modificar estas líneas específicas:**

```bash
# Buscar las líneas que contienen:
local   all             all                                     peer
host    all             all             127.0.0.1/32            ident

# Cambiarlas por:
local   all             all                                     md5
host    all             all             127.0.0.1/32            md5
```

**¿Qué significa cada método de autenticación?**
- **peer**: Usa el usuario del sistema operativo (requiere mismo nombre)
- **ident**: Usa servicio ident del sistema 
- **md5**: Usa contraseña encriptada (lo que necesitamos)

```bash
# Reiniciar PostgreSQL para aplicar cambios
sudo systemctl restart postgresql

# Verificar que sigue corriendo
sudo systemctl status postgresql
```

#### Verificación de Configuración PostgreSQL

```bash
# Probar conexión con el nuevo usuario
PGPASSWORD=issuernode_password psql -h localhost -U issuernode -d issuernode_db

# Una vez conectado, probar funcionalidad básica:
```

```sql
-- Crear tabla de prueba
CREATE TABLE test_table (id SERIAL PRIMARY KEY, data TEXT);

-- Insertar datos de prueba
INSERT INTO test_table (data) VALUES ('test data');

-- Consultar datos
SELECT * FROM test_table;

-- Limpiar prueba
DROP TABLE test_table;

-- Salir
\q
```

### Redis - Cache y Cola de Trabajos

#### ¿Por qué Redis?
- **In-Memory Storage**: Acceso extremadamente rápido a datos cached
- **Data Structures**: Soporte nativo para listas, sets, hashes
- **Pub/Sub**: Comunicación asíncrona entre servicios
- **Persistence**: Opcional, para recuperación tras reinicio

#### Instalación

```bash
# Ubuntu/Debian
sudo apt install -y redis-server

# CentOS/RHEL
sudo yum install -y redis

# Fedora  
sudo dnf install -y redis

# Arch Linux
sudo pacman -S redis
```

#### Configuración Personalizada

En lugar de usar la configuración por defecto, crearemos una configuración específica para el proyecto:

```bash
# Crear directorio para configuración personalizada
mkdir -p $HOME/redis-config

# Crear archivo de configuración personalizado
cat > $HOME/redis-config/redis.conf << 'EOF'
# Configuración Redis para Privado ID Issuer-Node

# === CONFIGURACIÓN DE RED ===
# Solo acepta conexiones desde localhost (seguridad)
bind 127.0.0.1

# Puerto estándar Redis
port 6379

# Timeout de conexiones inactivas (5 minutos)
timeout 300

# TCP keepalive (detección de conexiones perdidas)
tcp-keepalive 300

# Backlog de conexiones TCP
tcp-backlog 511

# === CONFIGURACIÓN DE SEGURIDAD ===
# Modo protegido activado (solo localhost sin auth)
protected-mode yes

# === CONFIGURACIÓN DE PERSISTENCIA ===
# Directorio de trabajo (donde se guardan los archivos RDB/AOF)
dir $HOME/redis-config/

# Configuración de snapshots automáticos
# save <segundos> <cambios>: Crear snapshot si hay X cambios en Y segundos
save 900 1      # Si hay 1 cambio en 15 minutos
save 300 10     # Si hay 10 cambios en 5 minutos  
save 60 10000   # Si hay 10000 cambios en 1 minuto

# Nombre del archivo de snapshot
dbfilename dump.rdb

# === CONFIGURACIÓN DE MEMORIA ===
# Política de evicción cuando se llena la memoria
# allkeys-lru: Elimina claves menos usadas recientemente
maxmemory-policy allkeys-lru

# === CONFIGURACIÓN DE LOGGING ===
# Nivel de log: debug, verbose, notice, warning
loglevel notice

# Archivo de log
logfile $HOME/redis-config/redis.log

# === CONFIGURACIÓN DE BASE DE DATOS ===
# Número de bases de datos (0-15 por defecto)
databases 16

# === CONFIGURACIÓN DE PROCESO ===
# Archivo donde guardar el PID del proceso
pidfile $HOME/redis-config/redis.pid

# Ejecutar como daemon (en background)
daemonize yes
EOF

# Establecer permisos apropiados
chmod 644 $HOME/redis-config/redis.conf
```

#### Script de Control Redis

```bash
cat > $HOME/redis-control.sh << 'EOF'
#!/bin/bash

# Configuración
REDIS_CONFIG="$HOME/redis-config/redis.conf"
REDIS_PID_FILE="$HOME/redis-config/redis.pid"
REDIS_LOG_FILE="$HOME/redis-config/redis.log"

# Función para verificar si Redis está corriendo
is_redis_running() {
    if [ -f "$REDIS_PID_FILE" ]; then
        local pid=$(cat "$REDIS_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0  # Está corriendo
        fi
    fi
    return 1  # No está corriendo
}

case "$1" in
    start)
        echo "🚀 Iniciando Redis..."
        
        # Verificar si ya está corriendo
        if is_redis_running; then
            echo "⚠️ Redis ya está corriendo (PID: $(cat $REDIS_PID_FILE))"
            exit 0
        fi
        
        # Crear directorio si no existe
        mkdir -p "$(dirname "$REDIS_CONFIG")"
        
        # Iniciar Redis con configuración personalizada
        redis-server "$REDIS_CONFIG"
        
        # Esperar un momento y verificar
        sleep 2
        if redis-cli ping > /dev/null 2>&1; then
            echo "✅ Redis iniciado correctamente"
            echo "📊 PID: $(cat $REDIS_PID_FILE)"
            echo "📝 Log: $REDIS_LOG_FILE"
        else
            echo "❌ Error al iniciar Redis"
            echo "🔍 Revisa el log: tail -f $REDIS_LOG_FILE"
            exit 1
        fi
        ;;
        
    stop)
        echo "🛑 Deteniendo Redis..."
        
        if is_redis_running; then
            # Usar shutdown de Redis para parada limpia
            redis-cli shutdown
            
            # Esperar a que termine
            local count=0
            while is_redis_running && [ $count -lt 10 ]; do
                sleep 1
                count=$((count + 1))
            done
            
            if is_redis_running; then
                echo "⚠️ Forzando cierre de Redis..."
                kill -9 $(cat "$REDIS_PID_FILE")
                rm -f "$REDIS_PID_FILE"
            fi
            
            echo "✅ Redis detenido"
        else
            echo "ℹ️ Redis no estaba corriendo"
        fi
        ;;
        
    restart)
        echo "🔄 Reiniciando Redis..."
        $0 stop
        sleep 2
        $0 start
        ;;
        
    status)
        echo "📊 Estado de Redis:"
        
        if is_redis_running; then
            echo "✅ Redis está corriendo (PID: $(cat $REDIS_PID_FILE))"
            
            # Mostrar información del servidor
            echo ""
            echo "📈 Información del servidor:"
            redis-cli info server | grep -E "(redis_version|uptime_in_seconds|tcp_port|process_id)"
            
            # Mostrar información de memoria
            echo ""
            echo "💾 Uso de memoria:"
            redis-cli info memory | grep -E "(used_memory_human|used_memory_peak_human)"
            
        else
            echo "❌ Redis no está corriendo"
            
            # Mostrar últimas líneas del log si existe
            if [ -f "$REDIS_LOG_FILE" ]; then
                echo ""
                echo "🔍 Últimas líneas del log:"
                tail -5 "$REDIS_LOG_FILE"
            fi
        fi
        ;;
        
    test)
        echo "🧪 Probando funcionalidad de Redis..."
        
        if ! redis-cli ping > /dev/null 2>&1; then
            echo "❌ Redis no responde a ping"
            exit 1
        fi
        
        # Test de escritura/lectura
        local test_key="issuer_test_$(date +%s)"
        local test_value="test_data_$(date +%s)"
        
        echo "📝 Test de escritura..."
        if redis-cli set "$test_key" "$test_value" > /dev/null; then
            echo "✅ Escritura exitosa"
        else
            echo "❌ Error en escritura"
            exit 1
        fi
        
        echo "📖 Test de lectura..."
        local retrieved_value=$(redis-cli get "$test_key")
        if [ "$retrieved_value" = "$test_value" ]; then
            echo "✅ Lectura exitosa"
        else
            echo "❌ Error en lectura. Esperado: $test_value, Obtenido: $retrieved_value"
            exit 1
        fi
        
        # Limpiar datos de test
        redis-cli del "$test_key" > /dev/null
        echo "✅ Test completado exitosamente"
        
        # Test de conexión con URL completa (como la usa issuer-node)
        echo "🔗 Test de conexión con URL..."
        if redis-cli -u redis://localhost:6379 ping > /dev/null 2>&1; then
            echo "✅ Conexión URL exitosa"
        else
            echo "❌ Error en conexión URL"
            exit 1
        fi
        ;;
        
    logs)
        echo "📝 Mostrando logs de Redis..."
        if [ -f "$REDIS_LOG_FILE" ]; then
            tail -f "$REDIS_LOG_FILE"
        else
            echo "❌ Archivo de log no encontrado: $REDIS_LOG_FILE"
        fi
        ;;
        
    *)
        echo "Uso: $0 {start|stop|restart|status|test|logs}"
        echo ""
        echo "Comandos:"
        echo "  start   - Iniciar Redis"
        echo "  stop    - Detener Redis" 
        echo "  restart - Reiniciar Redis"
        echo "  status  - Mostrar estado y estadísticas"
        echo "  test    - Ejecutar tests de funcionalidad"
        echo "  logs    - Mostrar logs en tiempo real"
        exit 1
        ;;
esac
EOF

chmod +x $HOME/redis-control.sh
```

#### Iniciar y Verificar Redis

```bash
# Iniciar Redis con configuración personalizada
$HOME/redis-control.sh start

# Verificar estado
$HOME/redis-control.sh status

# Ejecutar tests
$HOME/redis-control.sh test
```

### HashiCorp Vault - Gestión de Claves Criptográficas

#### ¿Por qué Vault?
- **Secret Management**: Almacenamiento seguro de claves privadas
- **Dynamic Secrets**: Generación automática de credenciales temporales
- **Audit Trail**: Log completo de acceso a secretos
- **Encryption as a Service**: Cifrado sin exponer claves
- **Plugin Architecture**: Extensible para algoritmos específicos

#### Instalación de Vault

```bash
# Opción A: Descarga directa del binario oficial (Recomendado)
cd /tmp

# Descargar la versión más reciente estable
wget https://releases.hashicorp.com/vault/1.15.2/vault_1.15.2_linux_amd64.zip

# Verificar integridad (opcional)
wget https://releases.hashicorp.com/vault/1.15.2/vault_1.15.2_SHA256SUMS
sha256sum -c vault_1.15.2_SHA256SUMS --ignore-missing

# Descomprimir
unzip vault_1.15.2_linux_amd64.zip

# Mover a directorio ejecutable
sudo mv vault /usr/local/bin/

# Verificar instalación
vault version
```

#### Configuración Vault para Desarrollo (Método Simplificado)

Para este setup de desarrollo, usaremos Vault en modo desarrollo sin systemd:

```bash
# Crear directorio para datos de Vault
mkdir -p $HOME/vault-data
mkdir -p $HOME/vault-config
mkdir -p $HOME/vault-plugins

# Crear configuración de Vault
cat > $HOME/vault-config/vault.hcl << 'EOF'
# Configuración Vault para Privado ID Issuer-Node

# === ALMACENAMIENTO ===
# Usar almacenamiento en archivo (para desarrollo)
storage "file" {
  path = "$HOME/vault-data"
}

# === LISTENER ===
# Escuchar en localhost puerto 8200 sin TLS
listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = 1
}

# === CONFIGURACIÓN GENERAL ===
# Habilitar interfaz web
ui = true

# Deshabilitar mlock (no disponible en algunos containers)
disable_mlock = true

# Directorio de plugins personalizado
plugin_directory = "$HOME/vault-plugins"

# === LOGGING ===
# Nivel de log
log_level = "INFO"
EOF

# Script de control de Vault
cat > $HOME/vault-control.sh << 'EOF'
#!/bin/bash

VAULT_CONFIG="$HOME/vault-config/vault.hcl"
VAULT_DATA_DIR="$HOME/vault-data"
VAULT_LOG="$HOME/vault-config/vault.log"
VAULT_PID_FILE="$HOME/vault-config/vault.pid"

# Configurar variables de entorno
export VAULT_ADDR='http://127.0.0.1:8200'

case "$1" in
    start)
        echo " Iniciando Vault..."
        
        # Verificar si ya está corriendo
        if curl -s "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; then
            echo "⚠️ Vault ya está corriendo"
            exit 0
        fi
        
        # Crear directorios necesarios
        mkdir -p "$(dirname "$VAULT_CONFIG")"
        mkdir -p "$VAULT_DATA_DIR"
        
        # Expandir variables en configuración
        envsubst < "$VAULT_CONFIG" > "$VAULT_CONFIG.expanded"
        
        # Iniciar Vault en background
        nohup vault server -config="$VAULT_CONFIG.expanded" > "$VAULT_LOG" 2>&1 &
        echo $! > "$VAULT_PID_FILE"
        
        # Esperar que inicie
        echo "⏳ Esperando que Vault inicie..."
        local count=0
        while ! curl -s "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1 && [ $count -lt 30 ]; do
            sleep 1
            count=$((count + 1))
        done
        
        if curl -s "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; then
            echo " Vault iniciado correctamente"
            echo " Web UI disponible en: $VAULT_ADDR"
            echo " Log: $VAULT_LOG"
        else
            echo "❌ Error al iniciar Vault"
            echo "🔍 Revisa el log: tail -f $VAULT_LOG"
            exit 1
        fi
        ;;
        
    stop)
        echo " Deteniendo Vault..."
        
        # Intentar parada limpia
        if [ -f "$VAULT_PID_FILE" ]; then
            local pid=$(cat "$VAULT_PID_FILE")
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid"
                
                # Esperar que termine
                local count=0
                while kill -0 "$pid" 2>/dev/null && [ $count -lt 10 ]; do
                    sleep 1
                    count=$((count + 1))
                done
                
                # Si no termina, forzar
                if kill -0 "$pid" 2>/dev/null; then
                    kill -9 "$pid"
                fi
            fi
            rm -f "$VAULT_PID_FILE"
        fi
        
        # Matar cualquier proceso vault restante
        pkill -f "vault server" 2>/dev/null
        
        echo " Vault detenido"
        ;;
        
    status)
        echo "📊 Estado de Vault:"
        
        if curl -s "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; then
            echo " Vault está corriendo"
            
            # Mostrar información básica
            vault status 2>/dev/null || echo "ℹ️ No autenticado o sellado"
            
        else
            echo "❌ Vault no está corriendo"
        fi
        ;;
        
    init)
        echo " Inicializando Vault..."
        
        if ! curl -s "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; then
            echo "❌ Vault no está corriendo. Ejecuta: $0 start"
            exit 1
        fi
        
        # Verificar si ya está inicializado
        if vault status 2>/dev/null | grep -q "Initialized.*true"; then
            echo "ℹ️ Vault ya está inicializado"
            exit 0
        fi
        
        echo "⚙️ Inicializando Vault con 1 clave compartida..."
        vault operator init -key-shares=1 -key-threshold=1 > "$HOME/vault-config/vault-keys.txt"
        
        if [ $? -eq 0 ]; then
            echo " Vault inicializado exitosamente"
            echo " Claves guardadas en: $HOME/vault-config/vault-keys.txt"
            echo ""
            echo "⚠️ IMPORTANTE: Guarda estas claves en lugar seguro:"
            cat "$HOME/vault-config/vault-keys.txt"
            
            # Extraer claves para uso automático
            grep "Unseal Key" "$HOME/vault-config/vault-keys.txt" | awk '{print $NF}' > "$HOME/vault-config/unseal-key"
            grep "Root Token" "$HOME/vault-config/vault-keys.txt" | awk '{print $NF}' > "$HOME/vault-config/root-token"
            
            chmod 600 "$HOME/vault-config/unseal-key" "$HOME/vault-config/root-token"
            
        else
            echo "❌ Error al inicializar Vault"
            exit 1
        fi
        ;;
        
    unseal)
        echo "🔓 Desbloqueando Vault..."
        
        if [ -f "$HOME/vault-config/unseal-key" ]; then
            local unseal_key=$(cat "$HOME/vault-config/unseal-key")
            vault operator unseal "$unseal_key"
            
            if [ $? -eq 0 ]; then
                echo " Vault desbloqueado exitosamente"
            else
                echo "❌ Error al desbloquear Vault"
                exit 1
            fi
        else
            echo "❌ Clave de desbloqueo no encontrada"
            echo " Inicializa Vault primero: $0 init"
            exit 1
        fi
        ;;
        
    login)
        echo " Autenticando en Vault..."
        
        if [ -f "$HOME/vault-config/root-token" ]; then
            local root_token=$(cat "$HOME/vault-config/root-token")
            vault login "$root_token"
            
            if [ $? -eq 0 ]; then
                echo " Autenticación exitosa"
            else
                echo "❌ Error en autenticación"
                exit 1
            fi
        else
            echo "❌ Token root no encontrado"
            echo " Inicializa Vault primero: $0 init"
            exit 1
        fi
        ;;
        
    setup-kv)
        echo "📦 Configurando almacén de secretos KV..."
        
        # Verificar autenticación
        if ! vault token lookup > /dev/null 2>&1; then
            echo "❌ No autenticado. Ejecuta: $0 login"
            exit 1
        fi
        
        # Habilitar KV v2 en path 'secret'
        if vault secrets list | grep -q "secret/"; then
            echo "ℹ️ Secret engine ya está habilitado"
        else
            vault secrets enable -path=secret -version=2 kv
            echo " Secret engine KV habilitado"
        fi
        
        # Verificar funcionamiento
        vault kv put secret/test key=value
        vault kv get secret/test
        vault kv delete secret/test
        
        echo " Secret engine configurado y probado"
        ;;
        
    logs)
        echo " Mostrando logs de Vault..."
        if [ -f "$VAULT_LOG" ]; then
            tail -f "$VAULT_LOG"
        else
            echo "❌ Archivo de log no encontrado: $VAULT_LOG"
        fi
        ;;
        
    *)
        echo "Uso: $0 {start|stop|status|init|unseal|login|setup-kv|logs}"
        echo ""
        echo "Comandos:"
        echo "  start    - Iniciar Vault"
        echo "  stop     - Detener Vault"
        echo "  status   - Mostrar estado"
        echo "  init     - Inicializar Vault (primera vez)"
        echo "  unseal   - Desbloquear Vault"
        echo "  login    - Autenticar con token root"
        echo "  setup-kv - Configurar almacén de secretos"
        echo "  logs     - Mostrar logs en tiempo real"
        echo ""
        echo "Flujo de configuración inicial:"
        echo "  1. $0 start"
        echo "  2. $0 init"
        echo "  3. $0 unseal"
        echo "  4. $0 login"
        echo "  5. $0 setup-kv"
        exit 1
        ;;
esac
EOF

chmod +x $HOME/vault-control.sh
```

#### Configuración Inicial de Vault

```bash
# Iniciar Vault
$HOME/vault-control.sh start

# Inicializar (solo primera vez)
$HOME/vault-control.sh init

# Desbloquear
$HOME/vault-control.sh unseal

# Autenticar
$HOME/vault-control.sh login

# Configurar almacén de secretos
$HOME/vault-control.sh setup-kv

# Verificar estado final
$HOME/vault-control.sh status
```

---

## 🏗️ Compilación del Issuer-Node

### Paso 1: Descarga del Código Fuente

```bash
# Crear directorio de desarrollo
mkdir -p $HOME/privado-id-development
cd $HOME/privado-id-development

# Clonar el repositorio oficial
git clone https://github.com/0xPolygonID/issuer-node.git
cd issuer-node

# Verificar la estructura del proyecto
ls -la
# Debería mostrar: cmd/, pkg/, docs/, go.mod, go.sum, etc.

# Ver la estructura de comandos disponibles
tree cmd/ -L 2
```

### Paso 2: Análisis de la Arquitectura del Código

#### Estructura de Directorios

```
issuer-node/
├── cmd/                          # Aplicaciones ejecutables
│   ├── platform/                 # API principal del issuer
│   ├── notifications/            # Servicio de notificaciones
│   ├── pending_publisher/        # Publicador de estados blockchain
│   ├── migrate/                  # Herramienta de migración DB
│   └── kms_priv_key_importer/   # Importador de claves privadas
├── pkg/                          # Librerías compartidas
│   ├── credentials/              # Lógica de credenciales
│   ├── db/                      # Acceso a base de datos
│   ├── kms/                     # Key Management System
│   └── blockchain/              # Interacción blockchain
├── internal/                     # Código interno (no exportable)
├── api/                         # Definiciones OpenAPI/Swagger
├── docs/                        # Documentación
└── migrations/                  # Migraciones de base de datos
```

### Paso 3: Gestión de Dependencias

```bash
cd $HOME/privado-id-development/issuer-node

# Verificar versión de Go en el proyecto
cat go.mod | head -5
# Debería mostrar: go 1.21 o superior

# Descargar dependencias
echo "📦 Descargando dependencias..."
go mod download

# Verificar integridad
go mod verify

# Limpiar caché si hay problemas
go clean -modcache
go mod tidy

# Ver dependencias principales
go list -m all | grep -E "(polygon|iden3|ethereum)"
```

### Paso 4: Compilación de Binarios

#### Script de Compilación Automatizada

```bash
cat > compile-all.sh << 'EOF'
#!/bin/bash

echo "🏗️ Compilando Privado ID Issuer-Node..."

# Configuración
BUILD_DIR="./build"
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Flags de compilación para optimización
LDFLAGS="-X main.version=$VERSION -X main.commit=$COMMIT -X main.buildTime=$BUILD_TIME -w -s"
BUILDFLAGS="-trimpath -buildvcs=false"

echo "📊 Información de build:"
echo "  Versión: $VERSION"
echo "  Commit: $COMMIT"
echo "  Tiempo: $BUILD_TIME"
echo ""

# Crear directorio de build
mkdir -p "$BUILD_DIR"
cd "$(dirname "$0")"

# Verificar que estamos en el directorio correcto
if [ ! -f "go.mod" ] || ! grep -q "github.com/polygonid/sh-id-platform" go.mod; then
    echo "❌ Error: No estás en el directorio raíz del proyecto issuer-node"
    echo " Ejecuta: cd \$HOME/privado-id-development/issuer-node"
    exit 1
fi

# Limpiar binarios anteriores
echo " Limpiando builds anteriores..."
rm -f ./issuer-api ./notifications ./pending-publisher ./migrate ./kms-importer

# Función para compilar un binario
compile_binary() {
    local name=$1
    local source=$2
    local output=$3
    
    echo " Compilando $name..."
    
    # Compilar con optimizaciones
    if go build $BUILDFLAGS -ldflags "$LDFLAGS" -o "$output" "$source"; then
        echo "   $name compilado exitosamente"
        
        # Mostrar información del binario
        local size=$(du -h "$output" | cut -f1)
        echo "  📊 Tamaño: $size"
        
        # Verificar que es ejecutable
        if [ -x "$output" ]; then
            echo "   Binario es ejecutable"
        else
            echo "  ⚠️ Warning: Binario no es ejecutable"
            chmod +x "$output"
        fi
        
        return 0
    else
        echo "  ❌ Error compilando $name"
        return 1
    fi
}

# Compilar cada aplicación
compile_binary "API Principal (issuer-api)" "./cmd/platform" "./issuer-api" || exit 1
compile_binary "Notificaciones" "./cmd/notifications" "./notifications" || exit 1
compile_binary "Publisher" "./cmd/pending_publisher" "./pending-publisher" || exit 1
compile_binary "Migrador" "./cmd/migrate" "./migrate" || exit 1

# kms-importer es opcional
if compile_binary "KMS Importer" "./cmd/kms_priv_key_importer" "./kms-importer"; then
    echo "  ℹ️ KMS Importer compilado (opcional)"
else
    echo "  ⚠️ KMS Importer falló (no crítico)"
fi

echo ""
echo " Compilación completada exitosamente!"
echo ""
echo "📋 Binarios generados:"
ls -lah ./issuer-api ./notifications ./pending-publisher ./migrate ./kms-importer 2>/dev/null | while read line; do
    echo "  $line"
done

echo ""
echo " Verificando binarios..."

# Test básico de cada binario
test_binary() {
    local binary=$1
    local name=$2
    
    if [ -f "$binary" ] && [ -x "$binary" ]; then
        # Intentar mostrar help/version
        if timeout 5 "$binary" --help > /dev/null 2>&1 || 
           timeout 5 "$binary" -h > /dev/null 2>&1 || 
           timeout 5 "$binary" version > /dev/null 2>&1; then
            echo "   $name: Funcional"
        else
            echo "  ⚠️ $name: Compilado pero puede tener problemas"
        fi
    else
        echo "  ❌ $name: No encontrado o no ejecutable"
    fi
}

test_binary "./issuer-api" "API Principal"
test_binary "./notifications" "Notificaciones" 
test_binary "./pending-publisher" "Publisher"
test_binary "./migrate" "Migrador"
test_binary "./kms-importer" "KMS Importer"

echo ""
echo " Para continuar:"
echo "  1. Configura las variables de entorno: nano .env-issuer"
echo "  2. Ejecuta migraciones: ./migrate up"
echo "  3. Inicia los servicios: ./start-all.sh"

EOF

chmod +x compile-all.sh
./compile-all.sh
```

#### Verificación de Compilación

```bash
# Verificar que todos los binarios se compilaron
ls -la issuer-api notifications pending-publisher migrate

# Verificar información de los binarios
file issuer-api
# Debería mostrar: ELF 64-bit LSB executable, x86-64

# Test rápido de funcionalidad (debería mostrar ayuda sin errores)
timeout 5 ./issuer-api --help 2>/dev/null && echo " issuer-api funcional"
timeout 5 ./migrate --help 2>/dev/null && echo " migrate funcional"
```

---

## ⚙️ Configuración de Variables

### Comprensión del Sistema de Configuración

El issuer-node utiliza variables de entorno para configuración, cargando automáticamente desde:
1. Variables del sistema
2. Archivo `.env-issuer` (si existe)
3. Valores por defecto hardcodeados

#### Categorías de Configuración

| Categoría | Propósito | Ejemplos |
|-----------|-----------|-----------|
| **Server** | Configuración del servidor HTTP | Puerto, URL pública |
| **Database** | Conexión a PostgreSQL | URL de conexión, credenciales |
| **Blockchain** | Conexión a Polygon | RPC URL, direcciones de contratos |
| **KMS** | Gestión de claves | Proveedores Vault/AWS, tokens |
| **Cache** | Configuración Redis | URL de conexión, TTL |
| **Logging** | Sistema de logs | Nivel, formato, destino |

### Paso 1: Archivo de Configuración Principal

```bash
cd $HOME/privado-id-development/issuer-node

# Crear archivo .env-issuer completo
cat > .env-issuer << 'EOF'
# ================================================================================
# PRIVADO ID ISSUER-NODE - CONFIGURACIÓN COMPLETA
# ================================================================================
# Este archivo contiene todas las variables de entorno necesarias para ejecutar
# el Issuer-Node de forma nativa (sin Docker)
# ================================================================================

# ===  CONFIGURACIÓN DEL SERVIDOR ===
# URL pública donde será accesible el issuer-node
# IMPORTANTE: Para desarrollo puedes usar localhost, para producción necesitas un dominio
ISSUER_SERVER_URL=http://localhost:3001

# Puerto donde escuchará el servidor HTTP
ISSUER_SERVER_PORT=3001

# ===  AUTENTICACIÓN DE API ===
# Credenciales para acceder a las APIs REST del issuer-node
# Estas credenciales se usan para HTTP Basic Auth
ISSUER_API_AUTH_USER=user-issuer
ISSUER_API_AUTH_PASSWORD=password-issuer

# === ⛓️ CONFIGURACIÓN BLOCKCHAIN (POLYGON AMOY) ===
# URL del RPC de Polygon Amoy (testnet)
# Puedes usar RPC público o crear cuenta en Infura/Alchemy para mejor rendimiento
ISSUER_ETHEREUM_URL=https://rpc-amoy.polygon.technology

# Dirección del contrato de estado en Polygon Amoy
# Este contrato gestiona los estados de las identidades
ISSUER_ETHEREUM_CONTRACT_ADDRESS=0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124

# Chain ID de Polygon Amoy (80002 en hexadecimal es 0x13882)
ISSUER_ETHEREUM_CHAIN_ID=80002

# ===  CONFIGURACIÓN DE CLAVES ===
# Path donde se almacena la clave pública para firmar estados
ISSUER_PUBLISH_KEY_PATH=pbkey

# Path para la clave de cuenta Ethereum (mismo que arriba para desarrollo)
ISSUER_ETHEREUM_TRANSFER_ACCOUNT_KEY_PATH=pbkey

# ===  CONFIGURACIÓN DE FRECUENCIAS ===
# Cada cuánto tiempo publicar estados en blockchain
ISSUER_ONCHAIN_PUBLISH_STATE_FREQUENCY=1m

# Cada cuánto tiempo verificar el estado de transacciones
ISSUER_ONCHAIN_CHECK_STATUS_FREQUENCY=1m

# === 🗄️ CONFIGURACIÓN DE BASE DE DATOS ===
# URL de conexión a PostgreSQL
# Formato: postgres://usuario:contraseña@host:puerto/basededatos?opciones
ISSUER_DATABASE_URL=postgres://issuernode:issuernode_password@localhost:5432/issuernode_db?sslmode=disable

# ===  CONFIGURACIÓN DE CACHE (REDIS) ===
# Proveedor de cache (redis o valkey)
ISSUER_CACHE_PROVIDER=redis

# URL de conexión a Redis
ISSUER_CACHE_URL=redis://localhost:6379

# ===  CONFIGURACIÓN KMS (KEY MANAGEMENT SYSTEM) ===
# Proveedor para claves BabyJubJub (usadas para DIDs)
# Opciones: vault, localstorage, aws-sm
ISSUER_KMS_BJJ_PROVIDER=vault

# Proveedor para claves Ethereum (usadas para transacciones blockchain)
# Opciones: vault, localstorage, aws-sm, aws-kms
ISSUER_KMS_ETH_PROVIDER=vault

# === 🏛️ CONFIGURACIÓN HASHICORP VAULT ===
# Dirección del servidor Vault
ISSUER_KEY_STORE_ADDRESS=http://127.0.0.1:8200

# Token de autenticación para Vault (obtenido durante configuración inicial)
ISSUER_KEY_STORE_TOKEN=TU_VAULT_ROOT_TOKEN_AQUI

# Token alternativo (algunos versiones usan esta variable)
ISSUER_VAULT_TOKEN=TU_VAULT_ROOT_TOKEN_AQUI

# Path donde están montados los secretos en Vault
ISSUER_KEY_STORE_PLUGIN_IDEN3_MOUNT_PATH=secret

# Configuración TLS para Vault (deshabilitado en desarrollo)
ISSUER_VAULT_TLS_ENABLED=false

# ===  CONFIGURACIÓN DE LOGGING ===
# Nivel de log: debug, info, warn, error
ISSUER_LOG_LEVEL=debug

# Modo de log: 1=json, 2=texto legible
ISSUER_LOG_MODE=2

# ===  CONFIGURACIÓN DE ENTORNO ===
# Entorno de ejecución (local, staging, production)
ISSUER_ENVIRONMENT=local

# Nombre del emisor (aparece en credenciales)
ISSUER_ISSUER_NAME=Mi Emisor de Prueba

# URL del logo del emisor (opcional)
ISSUER_ISSUER_LOGO=

# ===  CONFIGURACIÓN IPFS ===
# Gateway IPFS para almacenar metadatos de credenciales
ISSUER_IPFS_GATEWAY_URL=https://ipfs.io

# === 🔍 CONFIGURACIÓN DE RESOLVERS ===
# Servicio universal para resolver DIDs
ISSUER_UNIVERSAL_DID_RESOLVER_URL=https://dev.uniresolver.io/1.0/identifiers

# Archivo con configuración de resolvers por red
ISSUER_RESOLVER_PATH=./resolvers_settings.yaml

# ===  CONFIGURACIÓN DE CIRCUITOS ZK ===
# Directorio donde están los circuitos zero-knowledge
ISSUER_CIRCUIT_PATH=./pkg/credentials/circuits

# === ⚡ CONFIGURACIÓN DE PROVER ===
# Timeout para generación de pruebas ZK
ISSUER_PROVER_TIMEOUT=600s

# Habilitar generación nativa de pruebas
ISSUER_NATIVE_PROOF_GENERATION_ENABLED=true

# ===  CONFIGURACIÓN ADICIONAL ===
# Habilitar cache de esquemas
ISSUER_SCHEMA_CACHE=false

# Habilitar gestor de tipos de media
ISSUER_MEDIA_TYPE_MANAGER_ENABLED=true

# Directorio para almacenamiento local de claves (si se usa localstorage KMS)
ISSUER_KMS_PROVIDER_LOCAL_STORAGE_FILE_PATH=./localstoragekeys

# ================================================================================
# CONFIGURACIÓN AVANZADA (OPCIONAL)
# ================================================================================

# ===  UNIVERSAL LINKS (Para wallets móviles) ===
#ISSUER_UNIVERSAL_LINKS_BASE_URL=https://wallet.privado.id

# === 💳 CONFIGURACIÓN DE PAGOS ===
#ISSUER_PAYMENTS_SETTINGS_PATH=./payment_settings.yaml

# === ☁️ CONFIGURACIÓN AWS (Si usas AWS KMS/SecretsManager) ===
#ISSUER_KMS_AWS_ACCESS_KEY=tu-access-key
#ISSUER_KMS_AWS_SECRET_KEY=tu-secret-key
#ISSUER_KMS_AWS_REGION=us-east-1

# === 🔒 CONFIGURACIÓN VAULT AVANZADA ===
#ISSUER_VAULT_USERPASS_AUTH_ENABLED=false
#ISSUER_VAULT_USERPASS_AUTH_PASSWORD=password

# ================================================================================
# NOTAS IMPORTANTES:
# 1. Reemplaza TU_VAULT_ROOT_TOKEN_AQUI con tu token real de Vault
# 2. Para producción, usa un RPC privado (Infura/Alchemy) en lugar del público
# 3. Cambia las credenciales por defecto (user-issuer/password-issuer)
# 4. Para acceso externo, configura ISSUER_SERVER_URL con tu dominio real
# ================================================================================
EOF
```

### Paso 2: Configuración de Resolvers

```bash
# Crear configuración de resolvers para diferentes redes
cat > resolvers_settings.yaml << 'EOF'
# Configuración de resolvers para diferentes redes blockchain
# Este archivo define cómo resolver DIDs en diferentes redes

# Configuración para Polygon Amoy (testnet)
polygon:amoy:
  # URL del RPC de Polygon Amoy
  networkURL: https://rpc-amoy.polygon.technology
  # ID de la red (80002 para Amoy)
  chainID: 80002
  # Dirección del contrato de estado
  contractAddress: "0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124"
  # Método de resolución
  method: "polygonid"

# Configuración para Polygon Mainnet (producción)
polygon:main:
  networkURL: https://polygon-rpc.com
  chainID: 137
  contractAddress: "0x624ce98D2d27b20b8f8d521723Df8fC4db71D79D"
  method: "polygonid"

# Configuración para Ethereum Mainnet (si se necesita)
ethereum:main:
  networkURL: https://mainnet.infura.io/v3/YOUR_PROJECT_ID
  chainID: 1
  contractAddress: "0x..."
  method: "polygonid"

# Configuración de fallback universal
universal:
  # Servicio universal de resolución de DIDs
  resolverURL: "https://dev.uniresolver.io/1.0/identifiers"
  method: "universal"
  
# Configuración de timeouts
timeouts:
  # Timeout para llamadas RPC (en segundos)
  rpcTimeout: 30
  # Timeout para resolución de DIDs
  resolveTimeout: 10
  # Reintentos en caso de fallo
  retries: 3
EOF
```
