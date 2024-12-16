cmake_minimum_required(VERSION 3.10)

# Nombre del proyecto y estándar de C++
project(Paquet_sniffer_pro VERSION 0.1 LANGUAGES CXX)

# Activar funciones automáticas de Qt
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Configuración multiplataforma
if(WIN32)
    message(STATUS "Compilación para Windows")
    add_definitions(-DWIN32)
    include_directories("C:/Users/carlo/OneDrive/Documents/Universidad/QUINTO SEMESTRE/Redes de computadoras I/PROYECTO/npcap-sdk-1.13/Include")
    link_directories("C:/Users/carlo/OneDrive/Documents/Universidad/QUINTO SEMESTRE/Redes de computadoras I/PROYECTO/npcap-sdk-1.13/Lib/x64")
    set(PCAP_LIBS ws2_32 wpcap)

endif()

# Encontrar y configurar Qt
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core Widgets LinguistTools)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Widgets LinguistTools)

# Incluir los archivos de la librería QXlsx (ajusta la ruta según corresponda)
include_directories("C:/Users/carlo/Downloads/QXlsx-master/QXlsx-master/QXlsx")

# Fuentes del proyecto
set(PROJECT_SOURCES
    main.cpp
    v1.cpp
    v1.h
    v1.ui
    capturarpaquetes.cpp
    capturarpaquetes.h
    capturarpaquetes.ui
    AlmacenarTarjeta.cpp
    almacenartarjeta.h

)

# Generar ejecutable y procesar archivos UI
if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(Packet_sniffer_pro
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}

    )

else()
    add_executable(Packet_sniffer_pro
        ${PROJECT_SOURCES}
    )
endif()

# Añadir rutas necesarias
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# Vincular bibliotecas necesarias
target_link_libraries(Packet_sniffer_pro PRIVATE
    "C:/Users/carlo/OneDrive/Documents/Universidad/QUINTO SEMESTRE/Redes de computadoras I/PROYECTO/npcap-sdk-1.13/Lib/x64/Packet.lib"
    "C:/Users/carlo/OneDrive/Documents/Universidad/QUINTO SEMESTRE/Redes de computadoras I/PROYECTO/npcap-sdk-1.13/Lib/x64/wpcap.lib"
    ws2_32
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Widgets
)
