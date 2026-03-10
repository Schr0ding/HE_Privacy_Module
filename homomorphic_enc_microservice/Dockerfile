# Usamos Ubuntu 22.04 como base
FROM ubuntu:22.04

# Definir directorio de trabajo
WORKDIR /app

# Instalar herramientas de compilación y librerías necesarias:
# - build-essential, cmake, git, curl, etc.
# - meson y ninja para Pistache
# - libzstd-dev y zlib1g-dev para que SEAL use Zstd y Zlib del sistema
# - pkg-config por si CMake lo requiere para detectar librerías
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    libssl-dev \
    openssl \
    git \
    curl \
    libcurl4-openssl-dev \
    unzip \
    ca-certificates \
    meson \
    ninja-build \
    pkg-config \
    libzstd-dev \
    zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

# Actualizar certificados
RUN update-ca-certificates

# (Opcional) Ajustar parámetros Git
RUN git config --global http.version HTTP/1.1 && \
    git config --global http.postBuffer 104857600

# 1) Instalar Pistache con Meson
RUN git clone https://github.com/pistacheio/pistache.git /tmp/pistache \
    && cd /tmp/pistache \
    && meson setup build --buildtype=release \
    && meson compile -C build \
    && meson install -C build \
    && ldconfig \
    && rm -rf /tmp/pistache

# 2) Instalar la cabecera de nlohmann/json
RUN mkdir -p /usr/local/include/nlohmann \
    && curl -L https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp \
         -o /usr/local/include/nlohmann/json.hpp

# 3) Instalar Microsoft SEAL (v4.1.1) usando Zstd y Zlib del sistema, sin GSL
RUN git clone --depth 1 --branch v4.1.1 https://github.com/microsoft/SEAL.git /tmp/SEAL \
    && cd /tmp/SEAL \
    && mkdir build && cd build \
    && cmake \
       -DSEAL_BUILD_DEPS=OFF \
       -DSEAL_USE_ZSTD=OFF \
       -DZSTD_LIBRARY=/usr/lib/x86_64-linux-gnu/libzstd.so \
       -DZSTD_INCLUDE_DIR=/usr/include \
       -DSEAL_USE_ZLIB=ON \
       -DSEAL_USE_MSGSL=OFF \
       -DCMAKE_BUILD_TYPE=Release \
       -DCMAKE_INSTALL_PREFIX=/usr/local \
       .. \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /tmp/SEAL

# 4) Copiar el código de tu microservicio
COPY . /app

# 5) Compilar tu microservicio
RUN mkdir -p build \
    && cd build \
    && cmake .. \
    && make -j"$(nproc)"

# Exponer el puerto en el que escucha tu microservicio
EXPOSE 8889

# Ejecutar el binario
CMD ["./build/MicroServC"]
