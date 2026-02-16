# ☁️ Guía de Despliegue en Azure: AntimalwareHispan Platform

Esta guía detalla el proceso para desplegar la plataforma en un entorno de producción SaaS utilizando los servicios nativos de **Microsoft Azure**, garantizando escalabilidad, aislamiento y seguridad.

---

## 🏗️ 0. Arquitectura Objetivo

El despliegue se divide en dos planos lógicos para garantizar la seguridad del análisis de malware:

### **SaaS Analytics Plane (Producción)**
*   **Azure Container Apps (ACA)**: Entorno gestionado para la API (FastAPI) y los Workers (Celery).
*   **Azure Database for PostgreSQL**: Servidor flexible con aislamiento RLS.
*   **Azure Cache for Redis**: Broker de mensajes y caché de alta velocidad.
*   **Azure Storage (Blob)**: Almacenamiento persistente para muestras y reportes.
*   **Meilisearch**: Motor de búsqueda desplegado en ACA con volumen persistente (**Azure Files**).
*   **Azure Key Vault**: Gestión centralizada de secretos y certificados.

### **Sandbox Analysis Plane (Detonación)**
*   **Aislamiento de Red**: VM dedicada (Cuckoo/CAPE) en una Subnet aislada.
*   **Control de Egress**: NSG restrictivo para evitar fugas de red durante la detonación del malware.

---

## 🏷️ 1. Convención de Naming

Usa este patrón para mantener el orden en tu suscripción (Sugerencia):

| Recurso | Nombre Recomendado |
| :--- | :--- |
| **Resource Group** | `rg-hispan-antimalware-prod` |
| **ACR (Registry)** | `acrhispanmalprod` |
| **Environment ACA** | `cae-hispan-mal-prod` |
| **PostgreSQL** | `pg-hispan-mal-prod` |
| **Redis** | `redis-hispan-mal-prod` |
| **Storage Account** | `sthispanmalprod` |
| **Key Vault** | `kv-hispan-mal-prod` |

---

## 🐳 2. Configuración de Contenedores (Docker)

Debes crear dos Dockerfiles optimizados en la raíz de tu proyecto.

### **API (FastAPI)**
`Dockerfile.api`
```dockerfile
FROM python:3.11-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Dependencias de sistema mínimas
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
  && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

EXPOSE 8000

# Gunicorn + Uvicorn para producción
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "-w", "2", "-b", "0.0.0.0:8000", "main:app"]
```

### **Worker (Celery)**
`Dockerfile.worker`
```dockerfile
FROM python:3.11-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
  && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

# Ajusta las colas segun prioridad
CMD ["celery", "-A", "workers.celery_app", "worker", "--loglevel=info", "-Q", "triage,static,dynamic,reporting"]
```

---

## 🛠️ 3. Aprovisionamiento de Infraestructura (Azure CLI)

> [!IMPORTANT]
> Asegúrate de tener instalada la [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) y haber iniciado sesión con `az login`.

### **Inicialización y Registro**
```bash
az group create -n rg-hispan-antimalware-prod -l westeurope

# Crear Workspace de Logs
az monitor log-analytics workspace create \
  -g rg-hispan-antimalware-prod \
  -n log-hispan-mal-prod

# Obtener IDs de Logs
LOG_ID=$(az monitor log-analytics workspace show -g rg-hispan-antimalware-prod -n log-hispan-mal-prod --query customerId -o tsv)
LOG_KEY=$(az monitor log-analytics workspace get-shared-keys -g rg-hispan-antimalware-prod -n log-hispan-mal-prod --query primarySharedKey -o tsv)
```

### **Entorno de Container Apps y ACR**
```bash
az containerapp env create \
  -g rg-hispan-antimalware-prod \
  -n cae-hispan-mal-prod \
  --logs-workspace-id "$LOG_ID" \
  --logs-workspace-key "$LOG_KEY"

az acr create -g rg-hispan-antimalware-prod -n acrhispanmalprod --sku Basic
```

### **Base de Datos y Caché**
```bash
# PostgreSQL Flexible Server
az postgres flexible-server create \
  -g rg-hispan-antimalware-prod \
  -n pg-hispan-mal-prod \
  --tier Burstable --sku-name Standard_B1ms \
  --storage-size 64 \
  --version 15 \
  --admin-user pgadmin

# Azure Cache for Redis
az redis create \
  -g rg-hispan-antimalware-prod \
  -n redis-hispan-mal-prod \
  --sku Basic --vm-size c0
```

---

## 🚀 4. Despliegue de Componentes

### **Meilisearch con Persistencia**
Para Meilisearch, utilizamos **Azure Files** ya que requiere persistencia de estado:

1.  **Crear File Share**:
    ```bash
    az storage share create --account-name sthispanmalprod --name meili-data
    ```
2.  **Configurar Mount en ACA**:
    ```bash
    az containerapp env storage set \
      -g rg-hispan-antimalware-prod \
      -n cae-hispan-mal-prod \
      --storage-name meili-files \
      --access-mode ReadWrite \
      --azure-file-account-name sthispanmalprod \
      --azure-file-share-name meili-data \
      --azure-file-account-key "$(az storage account keys list -g rg-hispan-antimalware-prod -n sthispanmalprod --query [0].value -o tsv)"
    ```

### **Deploy API y Worker**
```bash
# API con Ingress Externo
az containerapp create \
  -n api -g rg-hispan-antimalware-prod \
  --environment cae-hispan-mal-prod \
  --image acrhispanmalprod.azurecr.io/antimalware/api:prod \
  --ingress external --target-port 8000

# Worker (Sin Ingress)
az containerapp create \
  -n worker -g rg-hispan-antimalware-prod \
  --environment cae-hispan-mal-prod \
  --image acrhispanmalprod.azurecr.io/antimalware/worker:prod \
  --ingress disabled
```

---

## 🔒 5. Seguridad y CI/CD

> [!TIP]
> Utiliza **Managed Identities** para que los servicios se autentiquen entre sí sin necesidad de manejar contraseñas en texto claro.

### **GitHub Actions: Despliegue Automático**
Crea un secreto `AZURE_CREDENTIALS` en GitHub y usa este flujo básico:

```yaml
name: Deploy to Azure
on:
  push:
    branches: [ "main" ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azure/login@v2
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      
      - name: Build & Push
        run: |
          az acr build -r acrhispanmalprod -t antimalware/api:${{ github.sha }} -f Dockerfile.api .
          az containerapp update -n api -g rg-hispan-antimalware-prod --image acrhispanmalprod.azurecr.io/antimalware/api:${{ github.sha }}
```

---

## ✅ 6. Checklist de Producción (Obligatorio)

- [ ] **HTTPS forzado** en todos los endpoints.
- [ ] **Private Endpoints** para la base de datos y Redis.
- [ ] **Managed Identity** habilitada para acceso a Blob Storage.
- [ ] **Key Vault** para secretos críticos (JWT, API Keys).
- [ ] **Aislamiento de Sandbox**: Red restringida para detonación dinámica.
- [ ] **Alertas de consumo**: Monitorizar escalado de instancias Celery.

---

> [!CAUTION]
> **Cámara de Contención**: Nunca ejecutes malware en la misma red que tu base de datos de producción. El Sandbox debe estar estrictamente aislado por NSGs.
