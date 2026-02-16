# AntimalwareHispan Platform - Quick Start Guide (Opcin A: Jinja2+HTMX)

## ✅ Estado del Proyecto
MVP Base funcional con pipeline de análisis completo y UI integrada.

## 🚀 Requisitos
- Python 3.10+
- Docker Desktop

---

## 🛠️ Setup en 3 Pasos

### 1. Iniciar Infraestructura
```powershell
docker-compose up -d
```
*Levanta PostgreSQL, Redis y Meilisearch.*

### 2. Configurar Python
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r backend/requirements.txt
```

### 3. Inicializar e Iniciar
```powershell
# (En una terminal con venv activo)
copy .env.example .env
python backend/scripts/init_db.py
cd backend
uvicorn main:app --reload
```

---

## 🖥️ Uso del Sistema
1. Abre **http://localhost:8000** en tu navegador.
2. Login con: `admin@demo.local` / `Admin123!`
3. Sube un archivo sospechoso en la seccin "Subir Muestra".
4. Observa el pipeline de anlisis en tiempo real.

---

## 🏗️ Stack Tecnolgico
- **Backend**: FastAPI (Python)
- **Frontend**: Jinja2 + Tailwind CSS + HTMX
- **Analizadores**: pefile, YARA, VirusTotal, Cuckoo CAPE
- **Base de Datos**: PostgreSQL + RLS
- **Tareas**: Celery + Redis
