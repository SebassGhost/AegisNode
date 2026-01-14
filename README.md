# AegisNode

**AegisNode** es un laboratorio de arquitectura de seguridad diseñado bajo una mentalidad *Zero Trust* y *APT-aware*.  
No es una herramienta ofensiva ni un exploit kit. Es un sistema modular pensado para **aprender, experimentar y demostrar** cómo se diseñan infraestructuras seguras que asumen compromiso parcial desde el inicio.

## Objetivo del proyecto

Diseñar y construir una arquitectura distribuida que:

- Asuma que **ningún nodo es confiable por defecto**
- Proteja la **confidencialidad, integridad y trazabilidad** de los datos
- Permita **auditoría y detección de manipulación**
- Sea **modular, portable y extensible**
- Sirva como **laboratorio personal de aprendizaje avanzado en ciberseguridad**

AegisNode está orientado a **defensa, observabilidad y control**, no a evasión ilegal

## Filosofía

AegisNode se rige por los siguientes principios:

- **Zero Trust real**: todo se valida, incluso lo interno
- **Asumir compromiso**: el sistema sigue funcionando aunque partes fallen
- **Seguridad por diseño**: no como capa añadida
- **Trazabilidad total**: todo evento deja evidencia verificable
- **Modularidad**: cada componente puede evolucionar de forma independiente

> *No se busca ocultar fallos, sino detectarlos y evidenciarlos.*


## Arquitectura general

AegisNode está compuesto por capas claramente separadas:

### Edge Node
- Punto más expuesto del sistema
- Captura datos del entorno
- Normaliza, cifra y firma antes de enviar
- Nunca confía en su propio input

### Secure Gateway
- Frontera de confianza
- Autenticación mutua (mTLS)
- Validación de firmas y timestamps
- Rate limiting y control de abuso

### Core Processing
- Descifrado y análisis de datos
- Procesamiento bajo políticas estrictas
- Auditoría criptográfica
- Detección de anomalías

### Secure Storage
- Persistencia cifrada
- Hash chaining para integridad histórica
- Backups cifrados y rotables

## Modelo de seguridad

- Cifrado simétrico: **AES-256-GCM**
- Firmas digitales: **Ed25519 / RSA**
- Comunicación segura: **mTLS**
- Logs firmados y encadenados por hash
- Secretos **no almacenados en claro**
- Claves efímeras y rotación periódica

El archivo `.env` **no contiene secretos reales**, solo referencias.

##  Uso desde terminal

AegisNode está diseñado para operar completamente desde CLI.

Ejemplo conceptual:

```bash
aegis init
aegis keys generate
aegis edge start
aegis gateway listen
aegis core process
aegis audit verify
```

Cada comando es explícito, auditable y reproducible.

## Testing

El proyecto incluye:

- Tests unitarios por módulo
- Tests de integración por flujo
- Validación de fallos controlados

La idea no es solo que funcione, sino **ver cómo falla**

## Estado del proyecto

AegisNode es un proyecto **en evolución constante**.

- Primero: aprendizaje y experimentación
- Luego: endurecimiento y optimización
- Finalmente: integración híbrida con otros toolkits

# ADVERTENCIA

Este proyecto es **educativo y defensivo**.

No está diseñado para:
- evadir sistemas reales
- vulnerar infraestructura ajena
- uso ilegal o no autorizado

El objetivo es **comprender cómo se diseñan sistemas seguros reales**

Proyecto desarrollado como laboratorio personal de arquitectura de seguridad y ciberseguridad avanzada.


 **AegisNode** — *Security is not secrecy, it is control, verification and traceability.*
