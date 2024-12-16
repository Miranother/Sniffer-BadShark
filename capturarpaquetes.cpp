#include "capturarpaquetes.h"
#include "./ui_capturarpaquetes.h"
#include "almacenartarjeta.h" // Para obtener el dispositivo seleccionado
#include <pcap/pcap.h>
#include <QDebug>
#include <QMessageBox>
#include <thread>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <winsock2.h> // Para inet_ntoa y ntohl en Windows
#include <QFile>
#include <QLabel>
#include <QDateTime>
#include <ws2tcpip.h>
#include "v1.h"  // Para la estructura ip (puede no estar disponible en Windows)


#include <QTextEdit>
#pragma comment(lib, "ws2_32.lib") // Necesario para funciones de red en Windows


#define IP_OFFMASK 0x1fff  // Mask for fragmenting bits
#define IP_MF 0x2000 // Define el flag "More Fragments" si no está definido

// Luego en tu código
// 1 si MF está establecido, 0 si no
// Estructura del encabezado IP
struct ip {
    unsigned char ip_hl : 4;         // Longitud del encabezado
    unsigned char ip_v : 4;          // VersiÃ³n
    unsigned char ip_tos;            // Tipo de servicio
    unsigned short ip_len;           // Longitud total
    unsigned short ip_id;            // Identificador
    unsigned short ip_off;           // Offset de fragmentaciÃ³n
    unsigned char ip_ttl;            // Tiempo de vida
    unsigned char ip_p;              // Protocolo
    unsigned short ip_sum;           // Suma de verificaciÃ³n
    struct in_addr ip_src, ip_dst;   // DirecciÃ³n IP de origen y destino
};

struct ether_header {
    u_char  ether_dhost[6];  // Dirección MAC de destino
    u_char  ether_shost[6];  // Dirección MAC de origen
    u_short ether_type;       // Tipo de protocolo
};

struct tcphdr {
    unsigned short th_sport; // Puerto de origen
    unsigned short th_dport; // Puerto de destino
    unsigned int th_seq;     // Secuencia
    unsigned int th_ack;     // Acuse de recibo
    unsigned char th_off:4;  // Longitud del encabezado
    unsigned char th_flags:4; // Flags
    unsigned short th_win;    // Ventana
    unsigned short th_sum;    // Suma de verificación
    unsigned short th_urp;    // Puerto urgente
};

struct udphdr {
    unsigned short uh_sport; // Puerto de origen
    unsigned short uh_dport; // Puerto de destino
    unsigned short uh_ulen;   // Longitud
    unsigned short uh_sum;    // Suma de verificación
};
// Función para convertir dirección MAC a cadena
void ether_ntoa(const u_char *mac, char *buffer) {
    sprintf(buffer, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Constructor
capturarpaquetes::capturarpaquetes(QWidget *parent)
    : QMainWindow(parent),
    ui(new Ui::capturarpaquetes),
    tableWidget(new QTableWidget(this)),
    pauseButton(new QPushButton("Pausa", this)),
    filterLineEdit(new QLineEdit(this)),
    detailsWidget(new QWidget(this)), // Nuevo widget para detalles
    dissectorWidget(new QWidget(this)), // Nuevo widget para disector
    paused(false) // Inicialmente no pausado
{
    ui->setupUi(this);
    setWindowTitle("BadShark - Captura de Paquetes");
    setFixedSize(1080, 720);
    setWindowIcon(QIcon("./BadShark.png"));
    // Configurar el QTableWidget
    tableWidget->setColumnCount(6);
    tableWidget->setHorizontalHeaderLabels({"Tiempo", "IP Fuente", "IP Destino", "Protocolo", "Tamaño","Info"});
    tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableWidget->horizontalHeader()->setStretchLastSection(true);
    tableWidget->setStyleSheet(
        "QTableWidget::item:hover {"
        "   background-color: transparent;" // Color de fondo al pasar el ratón
        "}");
    connect(tableWidget, &QTableWidget::itemSelectionChanged, this, &capturarpaquetes::actualizarSeleccion);

    // Configurar el QLineEdit
    QString filtroArchivo;
    QFile file("./filtro.txt");
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&file);
        filtroArchivo = in.readAll();
        file.close();
    }
    filterLineEdit->setText(filtroArchivo);
    connect(filterLineEdit, &QLineEdit::textChanged, this, &capturarpaquetes::actualizarFiltro);
    filterLineEdit->setPlaceholderText("Escribe un filtro aqui...");
    filterLineEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred); // Permitir que se expanda


    // Configurar el QPushButton
    connect(pauseButton, &QPushButton::clicked, this, &capturarpaquetes::togglePause);
    pauseButton->setFixedSize(80, 30);
    // Diseñar el layout
    QPushButton *saveButton = new QPushButton("Guardar CSV", this);
    saveButton->setFixedSize(80,30);
    connect(saveButton, &QPushButton::clicked, this, &capturarpaquetes::guardarPaquetesEnCSV);

    QHBoxLayout *topLayout = new QHBoxLayout();
    topLayout->addWidget(pauseButton);
    topLayout->addWidget(saveButton);
    topLayout->addWidget(filterLineEdit);


    QVBoxLayout *mainLayout = new QVBoxLayout();
    mainLayout->addLayout(topLayout);
    mainLayout->addWidget(tableWidget);

    // Crear un layout horizontal para los widgets de detalles y disector
    QHBoxLayout *detailsDissectorLayout = new QHBoxLayout();
    connect(tableWidget, &QTableWidget::itemClicked, this, [=](QTableWidgetItem* item) {
        filaSeleccionada = item->row();  // Guarda la fila seleccionada
        qDebug() << "Fila seleccionada:" << filaSeleccionada;
        qDebug() << "Número de filas en la tabla:" << tableWidget->rowCount();
        qDebug() << "Número de paquetes capturados:" << paquetesCapturados.size();

        // Verificar si la fila es válida
        if (filaSeleccionada >= 0 && filaSeleccionada < paquetesCapturados.size()) {
            Paquete paquete = paquetesCapturados.at(filaSeleccionada);  // Obtener el paquete de la lista
            qDebug() << "Guardando paquete: " << paquete.frameNumber;
            guardarPaqueteEnArchivo(paquete);  // Llamar a la función para guardar el paquete
        } else {
            qDebug() << "Índice de fila inválido.";
        }
    });

    // Crear un layout para el widget de detalles
    QVBoxLayout *detailsLayout = new QVBoxLayout(detailsWidget);
    detailsLayout->addWidget(new QLabel("Detalles del Paquete:", detailsWidget)); // Título

    // Crear y configurar el QTextEdit
    detailsTextEdit = new QTextEdit(this); // Crear un QTextEdit para mostrar detalles
    detailsTextEdit->setReadOnly(true); // Hacerlo de solo lectura
    detailsTextEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding); // Ajust

    // Agregar el QTextEdit al layout de detalles
    detailsLayout->addWidget(detailsTextEdit); // Agregar el QTextEdit al layout de detalles

    // Crear un layout para el widget de disector
    QVBoxLayout *dissectorLayout = new QVBoxLayout(dissectorWidget);
    dissectorLayout->addWidget(new QLabel("Disector de Paquetes:", dissectorWidget)); // Título

    // Crear y configurar el QTextEdit para el disector
    dissectorTextEdit = new QTextEdit(this);
    dissectorTextEdit->setReadOnly(true); // Hacerlo de solo lectura
    dissectorTextEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding); // Ajustar el tamaño
    dissectorTextEdit->setLineWrapMode(QTextEdit::WidgetWidth);  // Ajustar el texto al ancho del widget
    dissectorTextEdit->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded); // Habilitar scroll horizontal
    dissectorTextEdit->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded); // Habilitar scroll vertical

    // Agregar el QTextEdit al layout del disector
    dissectorLayout->addWidget(dissectorTextEdit);

    dissectorLayout->addStretch(); // Para que el contenido se empuje hacia arriba

    // Establecer políticas de tamaño para los widgets
    detailsWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    dissectorWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    // Agregar los widgets de detalles y disector al layout horizontal
    detailsDissectorLayout->addWidget(detailsWidget); // Agregar widget de detalles
    detailsDissectorLayout->addWidget(dissectorWidget); // Agregar widget de disector

    // Asegurarse de que ambos widgets ocupen el mismo espacio
    detailsDissectorLayout->setStretch(0, 1); // Establecer el estiramiento del primer widget
    detailsDissectorLayout->setStretch(1, 1); // Establecer el estiramiento del segundo widget

    detailsTextEdit->setFixedHeight(350); // Altura fija
    detailsTextEdit->setFixedWidth(600);  // Ancho fijo

    dissectorTextEdit->setFixedHeight(350);
    dissectorTextEdit->setFixedWidth(600);


    // Agregar el layout horizontal al layout principal
    mainLayout->addLayout(detailsDissectorLayout);

    // Crear el widget central y establecer el layout principal
    QWidget *centralWidget = new QWidget(this);
    centralWidget->setLayout(mainLayout);
    setCentralWidget(centralWidget);

    // Conectar la señal de clic en el QTableWidget para mostrar detalles
    connect(tableWidget, &QTableWidget::itemClicked, this, &capturarpaquetes::mostrarDetallesPaquete);

    // Obtener el nombre del dispositivo seleccionado
    QString deviceName = DispositivoSeleccionado::getNombre();
    qDebug() << "Dispositivo seleccionado:" << deviceName;

    // Iniciar la captura en un hilo separado
    std::thread captura([=]() {
        iniciarCaptura(deviceName);
    });
    captura.detach();
}

// Destructor
capturarpaquetes::~capturarpaquetes()
{
    delete ui;
}

// Alternar pausa/reanudar
void capturarpaquetes::togglePause()
{
    paused = !paused;
    pauseButton->setText(paused ? "Reanudar" : "Pausa");
}

// Iniciar la captura de paquetes
void capturarpaquetes::iniciarCaptura(const QString &deviceName)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Abrir el dispositivo para captura
    handle = pcap_open_live(deviceName.toStdString().c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        qDebug() << "Error al abrir el dispositivo:" << errbuf;
        return;
    }
    // Solo establecer startTime si es la primera vez que se inicia la captura
    if (startTime.isNull()) {
        startTime = QTime::currentTime();
    }
    startTime = QTime::currentTime();
    qDebug() << "Capturando paquetes en el dispositivo:" << deviceName;

    // Leer el filtro del archivo de texto
    QString filtroArchivo;
    QFile file("./filtro.txt");
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&file);

        filtroArchivo = in.readAll();
        file.close();
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;

    // Captura en bucle
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0 || paused) {
            continue; // Si estÃ¡ pausado, no procesar paquetes
        }

        // Verificar si el filtro ha cambiado
        QString filtroActual;
        QFile fileActual("./filtro.txt");
        if (fileActual.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream in(&fileActual);

            filtroActual = in.readAll();
            fileActual.close();
        }

        if (filtroActual != filtroArchivo) {
            filtroArchivo = filtroActual;
            // Reiniciar la captura con el nuevo filtro
            pcap_close(handle);
            handle = pcap_open_live(deviceName.toStdString().c_str(), BUFSIZ, 1, 1000, errbuf);
            if (handle == nullptr) {
                qDebug() << "Error al abrir el dispositivo:" << errbuf;
                return;
            }
        }

        // Verificar si hay un filtro en el archivo de texto
        if (!filtroArchivo.isEmpty()) {
            // Utilizar el filtro del archivo de texto
            if (procesarFiltroArchivo(packet, filtroArchivo)) {
                procesarPaquete(header, packet);
            }
        } else {
            // No hay filtro, procesar todos los paquetes
            procesarPaquete(header, packet);
        }
    }

    if (res == -1) {
        qDebug() << "Error al capturar paquetes:" << pcap_geterr(handle);
    }

    pcap_close(handle);
}

// Procesar el filtro del archivo de texto
bool capturarpaquetes::procesarFiltroArchivo(const u_char *packet, const QString &filtro)
{
    const struct ip *ipHeader = (struct ip *)(packet + 14); // Salta el encabezado Ethernet

    // Convertir direcciones IP
    QString source = QString::fromLatin1(inet_ntoa(ipHeader->ip_src));
    QString destination = QString::fromLatin1(inet_ntoa(ipHeader->ip_dst));

    // Determinar el protocolo
    QString protocol;
    switch (ipHeader->ip_p) {
    case IPPROTO_TCP:
        protocol = "TCP";
        break;
    case IPPROTO_UDP:
        protocol = "UDP";
        break;
    case IPPROTO_ICMP:
        protocol = "ICMP";
        break;
    default:
        protocol = "Otro";
        break;
    }

    // Verificar si el paquete coincide con el filtro
    if (filtro.toLower().contains("icmp") && protocol == "ICMP") {
        return true;
    } else if (filtro.toLower().contains("udp") && protocol == "UDP") {
        return true;
    } else if (filtro.toLower().contains("tcp") && protocol == "TCP") {
        return true;
    } else if (filtro.toLower().contains("host:") && (source.contains(filtro.mid(5).trimmed()) || destination.contains(filtro.mid(5).trimmed()))) {
        return true;
    }

    return false;
}

// Procesar cada paquete capturado
void capturarpaquetes::procesarPaquete(const struct pcap_pkthdr *header, const u_char *packet) {
    // Obtener el encabezado Ethernet
    const struct ether_header *ethHeader = (struct ether_header *)packet;

    // Obtener el encabezado IP (asumiendo que el paquete es IP)
    const struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header)); // Salta el encabezado Ethernet
    QString deviceName = DispositivoSeleccionado::getNombre();
    // Convertir direcciones IP
    QString source = QString::fromLatin1(inet_ntoa(ipHeader->ip_src));
    QString destination = QString::fromLatin1(inet_ntoa(ipHeader->ip_dst));
    // Resolver el nombre del dispositivo de origen
    QString sourceDeviceName = resolverNombreDispositivo(source);
    // Determinar el protocolo
    QString protocol;
    switch (ipHeader->ip_p) {
    case IPPROTO_TCP: {
        // Obtener el encabezado TCP
        const struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
        // Verificar si es TLSv1.3
        if (ntohs(tcpHeader->th_dport) == 443 || ntohs(tcpHeader->th_sport) == 443) {
            protocol = "TLSv1.3";
        } else {
            protocol = "TCP";
        }
        break;
    }
    case IPPROTO_UDP: {
        // Obtener el encabezado UDP
        const struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
        // Verificar si es mDNS
        if (ntohs(udpHeader->uh_dport) == 5353 || ntohs(udpHeader->uh_sport) == 5353) {
            protocol = "mDNS";
        }
        // Verificar si es SSDP
        else if (ntohs(udpHeader->uh_dport) == 1900 || ntohs(udpHeader->uh_sport) == 1900) {
            protocol = "SSDP";
        }
        // Verificar si es QUIC
        else if (ntohs(udpHeader->uh_dport) == 443 || ntohs(udpHeader->uh_sport) == 443) {
            protocol = "QUIC";
        } else {
            protocol = "UDP";
        }
        break;
    }
    case IPPROTO_ICMP:
        protocol = "ICMP";
        break;
    default:
        protocol = "Otro";
        break;
    }


    // Obtener el tamaño del paquete
    int packetSize = header->len;

    // Crear una instancia de Paquete
    Paquete paquete;
    paquete.frameNumber = tableWidget->rowCount() + 1; // Número de frame
    paquete.frameLength = packetSize; // Longitud del frame
    paquete.interfaceName = deviceName; // Cambia esto según tu lógica
    paquete.sourceDeviceName = sourceDeviceName; // Almacenar el nombre del dispositivo de origen

    // Calcular el tiempo transcurrido desde el inicio de la captura
    int elapsedMilliseconds = startTime.msecsTo(QTime::currentTime());
    int elapsedSeconds = elapsedMilliseconds / 1000; // Convertir a segundos
    int milliseconds = elapsedMilliseconds % 1000; // Obtener milisegundos restantes
    paquete.elapsedTime = QString("%1.%2").arg(elapsedSeconds).arg(milliseconds, 3, 10, QChar('0')); // Formato "segundos.milisegundos"


    QDateTime dateTime = QDateTime::fromSecsSinceEpoch(header->ts.tv_sec, Qt::UTC);
    QString readableTime = dateTime.toString("yyyy-MM-dd HH:mm:ss");
    paquete.arrivalTime = QString("%1.%2").arg(readableTime).arg(header->ts.tv_usec, 6, 10, QChar('0'));
    paquete.epochArrivalTime = header->ts.tv_sec; // Tiempo en epoch (cambia a long si es necesario)
    paquete.encapsulationType = "Ethernet"; // Tipo de encapsulación

    char srcMacStr[18]; // Buffer para la dirección MAC de origen
    char dstMacStr[18]; // Buffer para la dirección MAC de destino
    ether_ntoa(ethHeader->ether_shost, srcMacStr);
    ether_ntoa(ethHeader->ether_dhost, dstMacStr);

    paquete.srcMac = QString::fromLatin1(srcMacStr); // Dirección MAC de origen
    paquete.dstMac = QString::fromLatin1(dstMacStr); // Dirección MAC de destino
    paquete.ethType = QString::number(ntohs(ethHeader->ether_type)); // Tipo de Ethernet
    paquete.srcIP = source;
    paquete.dstIP = destination;
    paquete.ipVersion = "IPv4"; //
    paquete.ipHeaderLength = QString::number(ipHeader->ip_hl * 4); // Longitud del encabezado IP en bytes
    paquete.totalLength = QString::number(ntohs(ipHeader->ip_len)); // Longitud total del paquete IP
    paquete.identification = QString::number(ntohs(ipHeader->ip_id)); // Identificación del paquete IP
    paquete.flags = QString::number(ntohs(ipHeader->ip_off) & IP_MF ? 1 : 0); // Flags del paquete IP
    paquete.fragmentOffset = QString::number(ntohs(ipHeader->ip_off) & IP_OFFMASK); // Offset de fragmento
    paquete.ttl = QString::number(ipHeader->ip_ttl); // Tiempo de vida (TTL)
    paquete.protocol = protocol; // Protocolo (TCP, UDP, ICMP, etc.)
    paquete.headerChecksum = QString::number(ntohs(ipHeader->ip_sum)); // Checksum del encabezado IP

    // Si es un paquete TCP, extraer información adicional
    if (ipHeader->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
        paquete.tcpSrcPort = QString::number(ntohs(tcpHeader->th_sport)); // Puerto de origen TCP
        paquete.tcpDstPort = QString::number(ntohs(tcpHeader->th_dport)); // Puerto de destino TCP
        paquete.tcpSeqNumber = QString::number(ntohl(tcpHeader->th_seq)); // Número de secuencia TCP
        paquete.tcpAckNumber = QString::number(ntohl(tcpHeader->th_ack)); // Número de acuse de recibo TCP
        // Flags TCP
        paquete.tcpFlags = QString::number(tcpHeader->th_flags); // Flags TCP
        paquete.tcpWindowSize = QString::number(ntohs(tcpHeader->th_win)); // Tamaño de la ventana TCP
        paquete.tcpChecksum = QString::number(ntohs(tcpHeader->th_sum)); // Checksum TCP
        paquete.tcpUrgentPointer = QString::number(ntohs(tcpHeader->th_urp)); // Puntero urgente TCP
    }

    // Obtener la longitud de la carga útil
    int payloadOffset = sizeof(struct ether_header) + ipHeader->ip_hl * 4; // Offset para la carga útil
    int payloadLength = packetSize - payloadOffset; // Longitud de la carga útil

    // Asegúrate de que la longitud de la carga útil no sea negativa
    if (payloadLength > 0) {
        paquete.payloadLength = QString::number(payloadLength); // Longitud de la carga útil
        paquete.payloadData = QString::fromUtf8(reinterpret_cast<const char*>(packet + payloadOffset), payloadLength); // Datos de la carga útil
    } else {
        paquete.payloadLength = "0"; // Si no hay carga útil
        paquete.payloadData = ""; // Sin datos
    }

    // Agregar el paquete a la tabla
    agregarPaqueteATabla(header->ts, source, destination, protocol, packetSize,paquete.elapsedTime,paquete.sourceDeviceName);
    // Agregar el paquete a la lista de paquetes capturados
    paquetesCapturados.append(paquete);
}
// Agregar un paquete a la tabla
void capturarpaquetes::agregarPaqueteATabla(const struct timeval &timestamp, const QString &source, const QString &destination, const QString &protocol, int size, const QString &elapsedTime, const QString &sourceDeviceName) {
    // Convertir el tiempo a un formato legible
    QString timeString = QString("%1.%2").arg(timestamp.tv_sec).arg(timestamp.tv_usec, 6, 10, QChar('0'));

    // Insertar una nueva fila en la tabla
    int rowCount = tableWidget->rowCount();
    tableWidget->insertRow(rowCount);

    // Crear los elementos de la fila
    QTableWidgetItem *timeItem = new QTableWidgetItem(elapsedTime);
    QTableWidgetItem *sourceItem = new QTableWidgetItem(source);
    QTableWidgetItem *destinationItem = new QTableWidgetItem(destination);
    QTableWidgetItem *protocolItem = new QTableWidgetItem(protocol);
    QTableWidgetItem *sizeItem = new QTableWidgetItem(QString::number(size));
    QTableWidgetItem *deviceItem = new QTableWidgetItem(sourceDeviceName); // Nuevo elemento para el nombre del dispositivo

    // Determinar el color de fondo opaco basado en el protocolo
    QColor backgroundColor;
    if (protocol == "TCP") {
        backgroundColor = QColor(135, 206, 250, 100); // Azul claro opaco
    } else if (protocol == "UDP") {
        backgroundColor = QColor(144, 238, 144, 100); // Verde claro opaco
    } else if (protocol == "ICMP") {
        backgroundColor = QColor(255, 255, 102, 100); // Amarillo claro opaco
    } else if (protocol == "TLSv1.3") {
        backgroundColor = QColor(0, 204, 204, 100); // Azul oscuro opaco
    } else if (protocol == "mDNS") {
        backgroundColor = QColor(255, 165, 0, 100); // Naranja opaco
    } else if (protocol == "SSDP") {
        backgroundColor = QColor(255, 192, 203, 100); // Rosa opaco
    } else if (protocol == "QUIC") {
        backgroundColor = QColor(230, 230, 250, 100); // Violeta opaco
    } else {
        backgroundColor = QColor(211, 211, 211, 100); // Gris claro opaco para otros
    }
    // Aplicar el color de fondo y mantener texto oscuro
    timeItem->setBackground(backgroundColor);
    sourceItem->setBackground(backgroundColor);
    destinationItem->setBackground(backgroundColor);
    protocolItem->setBackground(backgroundColor);
    sizeItem->setBackground(backgroundColor);
    deviceItem->setBackground(backgroundColor); // Color de fondo para el nombre del dispositivo

    timeItem->setForeground(Qt::black);
    sourceItem->setForeground(Qt::black);
    destinationItem->setForeground(Qt::black);
    protocolItem->setForeground(Qt::black);
    sizeItem->setForeground(Qt::black);
    deviceItem->setForeground(Qt::black); // Texto normal para el nombre del dispositivo

    // Agregar los elementos a la tabla
    tableWidget->setItem(rowCount, 0, timeItem);
    tableWidget->setItem(rowCount, 1, sourceItem);
    tableWidget->setItem(rowCount, 2, destinationItem);
    tableWidget->setItem(rowCount, 3, protocolItem);
    tableWidget->setItem(rowCount, 4, sizeItem);
    tableWidget->setItem(rowCount, 5, deviceItem); // Agregar el nombre del dispositivo a la tabla
}
void capturarpaquetes::actualizarSeleccion()
{
    // Iterar sobre todas las filas
    for (int row = 0; row < tableWidget->rowCount(); ++row) {
        for (int col = 0; col < tableWidget->columnCount(); ++col) {
            QTableWidgetItem *item = tableWidget->item(row, col);
            if (item) {
                if (item->isSelected()) {
                    item->setForeground(Qt::white); // Texto más brillante
                    item->setFont(QFont("Arial", 10, QFont::Bold)); // Texto en negrita
                    item->setBackground(item->background()); // Mantener el color de fondo
                } else {
                    item->setForeground(Qt::black); // Texto normal
                    item->setFont(QFont("Arial", 10, QFont::Normal)); // Texto normal
                }
            }
        }
    }
}





void capturarpaquetes::actualizarFiltro()
{
    QLineEdit* lineEditFiltro = findChild<QLineEdit*>(); // Buscar el QLineEdit en la UI
    if (lineEditFiltro) {
        connect(lineEditFiltro, &QLineEdit::returnPressed, this, &capturarpaquetes::procesarFiltro);
    }
}


void capturarpaquetes::procesarFiltro()
{
    QLineEdit* lineEditFiltro = findChild<QLineEdit*>(); // Buscar el QLineEdit en la UI
    if (lineEditFiltro) {
        disconnect(lineEditFiltro, &QLineEdit::returnPressed, this, &capturarpaquetes::procesarFiltro);

        QString textoFiltro = lineEditFiltro->text();
        if (textoFiltro.isEmpty()) {
            return;
        }

        // Verificar si se quiere quitar el filtro
        if (textoFiltro.toLower() == "none") {
            // Quitar el filtro del archivo
            QFile file("./filtro.txt");
            if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                QTextStream out(&file);
                out << "";
                file.close();
                qDebug() << "Filtro quitado";
                QMessageBox::information(this, "Filtro quitado", "Se ha quitado el filtro");
            } else {
                qDebug() << "Error al abrir el archivo para escribir.";
            }
            return;
        }

        // Validar el texto ingresado
        if      (textoFiltro.toLower().contains("icmp") ||
                textoFiltro.toLower().contains("udp") ||
                textoFiltro.toLower().contains("tcp") ||
                textoFiltro.toLower().contains("tlsv1.3") ||
                textoFiltro.toLower().contains("mdns") ||
                textoFiltro.toLower().contains("ssdp") ||
                textoFiltro.toLower().contains("quic")) {
            // Guardar el texto valido en el archivo
            QFile file("./filtro.txt");
            if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                QTextStream out(&file);
                out << textoFiltro << "\n";
                file.close();
                qDebug() << "Filtro guardado en filtro.txt";
                QMessageBox::information(this, "Filtro guardado", "Haz seleccionado: " + textoFiltro);
            } else {
                qDebug() << "Error al abrir el archivo para escribir.";
            }
        } else if (textoFiltro.toLower().startsWith("host:")) {
            // Validar el texto ingresado
            if (textoFiltro.toLower().startsWith("host:")) {
                QString dominio = textoFiltro.mid(5).trimmed(); // Extrae el dominio del filtro y elimina espacios
                QString ipAddress = resolverDominio(dominio); // Resuelve el dominio a IP
                if (!ipAddress.isEmpty()) {
                    // Guardar el filtro como dirección IP
                    QFile file("./filtro.txt");
                    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                        QTextStream out(&file);
                        out << "host: " << ipAddress << "\n"; // Guarda el filtro como IP
                        file.close();
                        qDebug() << "Filtro guardado en filtro.txt";
                        QMessageBox::information(this, "Filtro guardado", "Haz seleccionado: " + dominio);
                    } else {
                        qDebug() << "Error al abrir el archivo para escribir.";
                    }
                } else {
                    // Dominio no existe, mostrar mensaje de error
                    QMessageBox::critical(this, "Error", "El dominio " + dominio + " no se pudo resolver.");
                    lineEditFiltro->clear(); // Limpiar el QLineEdit
                }
            } else {
                // Dominio no existe, mostrar mensaje de error
                QMessageBox::critical(this, "Error", "El dominio " + dominio + " no existe.");
                lineEditFiltro->clear(); // Limpiar el QLineEdit
            }
        } else {
            QMessageBox::warning(this, "Filtro no valido", "El filtro ingresado no es valido. Por favor, ingrese un filtro que contenga ICMP, UDP, TCP o host: (dominio), TLSV1.3,MDNS,SSDP,QUIC,none(quitar filtro)");
            lineEditFiltro->clear(); // Limpiar el QLineEdit
            return;
        }
    }

    // Obtener el dispositivo seleccionado
    QString deviceName = DispositivoSeleccionado::getNombre();

    // Iniciar la captura en un hilo separado
    std::thread captura([=]() {
        iniciarCaptura(deviceName);
    });
    captura.detach();
}
QString capturarpaquetes::resolverDominio(const QString &dominio) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return QString("Error al inicializar Winsock");
    }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP

    // Llamar a getaddrinfo
    int status = getaddrinfo(dominio.toStdString().c_str(), NULL, &hints, &res);
    if (status != 0) {
        WSACleanup(); // Limpiar Winsock
        return QString("Error al resolver el dominio: ") + QString(gai_strerror(status));
    }

    // Convertir la dirección IP a un QString
    char ipstr[INET_ADDRSTRLEN];
    QString lastIpAddress; // Para almacenar la última dirección IP encontrada

    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        void *addr = &((struct sockaddr_in *)p->ai_addr)->sin_addr;
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        lastIpAddress = QString(ipstr); // Actualizar con la última dirección IP
    }

    freeaddrinfo(res); // Liberar la memoria
    WSACleanup(); // Limpiar Winsock

    if (lastIpAddress.isEmpty()) {
        return QString("No se pudo resolver el dominio");
    }

    return lastIpAddress; // Devuelve la última dirección IP como QString
}
void capturarpaquetes::guardarPaqueteEnArchivo(const Paquete &paquete)
{
    QFile file("paquete_actual.txt"); // Cambia el nombre del archivo si es necesario
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) { // Abrir en modo de escritura
        QTextStream out(&file);

        // Información común para todos los paquetes
        out << "Número de frame: " << paquete.frameNumber << "\n";
        out << "Longitud del frame: " << paquete.frameLength << "\n";
        out << "Nombre de la interfaz: " << paquete.interfaceName << "\n";
        out << "De donde proviene el paquete: " << paquete.sourceDeviceName << "\n";
        out << "Hora de llegada: " << paquete.arrivalTime << "\n";
        out << "Hora de llegada en formato epoch: " << paquete.epochArrivalTime << "\n";
        out << "Tipo de encapsulación: " << paquete.encapsulationType << "\n";
        out << "Dirección MAC de origen: " << paquete.srcMac << "\n";
        out << "Dirección MAC de destino: " << paquete.dstMac << "\n";
        out << "Tipo de Ethernet: " << paquete.ethType << "\n";
        out << "Dirección IP de origen: " << paquete.srcIP << "\n";
        out << "Dirección IP de destino: " << paquete.dstIP << "\n";
        out << "Versión de IP: " << paquete.ipVersion << "\n";
        out << "Longitud del encabezado IP: " << paquete.ipHeaderLength << "\n";
        out << "Longitud total del paquete IP: " << paquete.totalLength << "\n";
        out << "Identificación del paquete IP: " << paquete.identification << "\n";
        out << "Flags del paquete IP: " << paquete.flags << "\n";
        out << "Offset de fragmento: " << paquete.fragmentOffset << "\n";
        out << "Tiempo de vida (TTL): " << paquete.ttl << "\n";
        out << "Protocolo: " << paquete.protocol << "\n";
        out << "Checksum del encabezado IP: " << paquete.headerChecksum << "\n";

        // Información específica según el tipo de paquete
        if (paquete.protocol == "TCP") {
            out << "Puerto de origen TCP: " << paquete.tcpSrcPort << "\n";
            out << "Puerto de destino TCP: " << paquete.tcpDstPort << "\n";
            out << "Número de secuencia TCP: " << paquete.tcpSeqNumber << "\n";
            out << "Número de acuse de recibo TCP: " << paquete.tcpAckNumber << "\n";
            out << "Flags TCP: " << paquete.tcpFlags << "\n";
            out << "Tamaño de la ventana TCP: " << paquete.tcpWindowSize << "\n";
            out << "Checksum TCP: " << paquete.tcpChecksum << "\n";
            out << "Puntero urgente TCP: " << paquete.tcpUrgentPointer << "\n";
        } else if (paquete.protocol == "UDP") {
            out << "Puerto de origen UDP: " << paquete.tcpSrcPort << "\n"; // Puedes usar tcpSrcPort para UDP también
            out << "Puerto de destino UDP: " << paquete.tcpDstPort << "\n"; // Puedes usar tcpDstPort para UDP también
            // Agrega más información específica de UDP si es necesario
        } else if (paquete.protocol == "ICMP") {
            // Agrega información específica de ICMP si es necesario
        }

        // Información de la carga útil
        out << "Longitud de la carga útil: " << paquete.payloadLength << "\n";
        out << "Datos de la carga útil: " << paquete.payloadData << "\n";

        file.close();
    } else {
        qDebug() << "Error al abrir el archivo para escribir.";
    }
}


void capturarpaquetes::mostrarDetallesPaquete(QTableWidgetItem *item) {
    // Obtener la fila seleccionada
    filaSeleccionada = item->row();

    // Verificar que la fila seleccionada sea válida
    if (filaSeleccionada >= 0 && filaSeleccionada < paquetesCapturados.size()) {
        // Obtener el paquete correspondiente de la lista de paquetes capturados
        Paquete paquete = paquetesCapturados.at(filaSeleccionada);

        // Llamar a la función para guardar el paquete en un archivo
        guardarPaqueteEnArchivo(paquete);

        // Leer el contenido del archivo y actualizar los widgets
        QFile file("paquete_actual.txt"); // Archivo original
        if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QByteArray contenido = file.readAll(); // Leer todo el contenido del archivo
            file.close();

            // Mostrar el contenido normal en el detailsTextEdit
            detailsTextEdit->setPlainText(QString::fromUtf8(contenido));

            // Convertir a hexadecimal
            QString contenidoHex = convertirAHexadecimal(contenido); // Convertir a hexadecimal

            // Mostrar el contenido hexadecimal en el dissectorTextEdit
            dissectorTextEdit->setPlainText(contenidoHex);

        } else {
            qDebug() << "Error al abrir el archivo para leer.";
            detailsTextEdit->setPlainText("Error al abrir el archivo para leer."); // Mensaje de error
            dissectorTextEdit->setPlainText(""); // Vaciar el widget de disector
        }
    } else {
        qDebug() << "Fila seleccionada no válida.";
    }
}


// Función auxiliar para convertir datos a formato hexadecimal
QString capturarpaquetes::convertirAHexadecimal(const QByteArray &data) {
    QString hexString;
    const int bytesPerLine = 16; // Número de bytes por línea
    for (int i = 0; i < data.size(); ++i) {
        // Añadir el byte en formato hexadecimal con más espacios
        hexString.append(QString::number(static_cast<unsigned char>(data[i]), 16).rightJustified(2, '0')).append("      "); // Seis espacios
        if ((i + 1) % bytesPerLine == 0) {
            hexString.append("\n\n\n"); // Añadir dos saltos de línea adicionales para más espacio
        }
    }
    return hexString.trimmed(); // Eliminar el espacio final
}

void capturarpaquetes::guardarPaquetesEnCSV() {
    QFile file("paquetes.csv"); // Nombre del archivo CSV
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);

        // Escribir encabezados
        out << "Paquete,Tiempo,IP Fuente,IP Destino,Protocolo,Tam,Info\n";

        // Escribir cada paquete capturado
        for (const Paquete &paquete : paquetesCapturados) {
            out
                << paquete.frameNumber << ","
                << paquete.elapsedTime << "," // Tiempo
                << paquete.srcIP << ","       // IP Fuente
                << paquete.dstIP << ","       // IP Destino
                << paquete.protocol << ","     // Protocolo
                << paquete.frameLength << "," // Tamaño
                << paquete.sourceDeviceName <<"\n";
        }

        file.close();
        QMessageBox::information(this, "Éxito", "Paquetes guardados en paquetes.csv");

        // Ahora leer el contenido de paquete_actual.txt y agregarlo al CSV
        QFile paqueteActualFile("paquete_actual.txt");
        if (paqueteActualFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream in(&paqueteActualFile);
            QString contenidoPaqueteActual = in.readAll(); // Leer todo el contenido

            // Reemplazar caracteres acentuados y "ñ"
            contenidoPaqueteActual.replace("á", "a");
            contenidoPaqueteActual.replace("é", "e");
            contenidoPaqueteActual.replace("í", "i");
            contenidoPaqueteActual.replace("ó", "o");
            contenidoPaqueteActual.replace("ú", "u");
            contenidoPaqueteActual.replace("ñ", "n");
            contenidoPaqueteActual.replace("Á", "A");
            contenidoPaqueteActual.replace("É", "E");
            contenidoPaqueteActual.replace("Í", "I");
            contenidoPaqueteActual.replace("Ó", "O");
            contenidoPaqueteActual.replace("Ú", "U");

            // Abrir el archivo CSV nuevamente para agregar la información
            if (file.open(QIODevice::Append | QIODevice::Text)) {
                out.setDevice(&file);
                out << "\nInformacion del paquete actual:\n"; // Agregar un encabezado para la información del paquete actual
                out << contenidoPaqueteActual; // Agregar el contenido del paquete actual
                file.close();
            } else {
                qDebug() << "Error al abrir el archivo CSV para agregar información.";
            }

            paqueteActualFile.close();
        } else {
            qDebug() << "Error al abrir paquete_actual.txt.";
        }
    } else {
        qDebug() << "Error al abrir el archivo para escribir.";
        QMessageBox::critical(this, "Error", "No se pudo guardar el archivo CSV.");
    }
}



QString capturarpaquetes::resolverNombreDispositivo(const QString &ip) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return QString("Error al inicializar Winsock");
    }

    struct sockaddr_in sa;
    sa.sin_family = AF_INET;

    // Convertir la dirección IP de QString a in_addr
    if (inet_pton(AF_INET, ip.toStdString().c_str(), &sa.sin_addr) <= 0) {
        WSACleanup();
        return QString("Dirección IP no válida");
    }

    // Usar gethostbyaddr para obtener el nombre del host
    struct hostent *he = gethostbyaddr((const char *)&sa.sin_addr, sizeof(sa.sin_addr), AF_INET);
    if (he != nullptr) {
        WSACleanup(); // Limpiar Winsock
        return QString::fromLatin1(he->h_name); // Devuelve el nombre del host
    }

    WSACleanup(); // Limpiar Winsock
    return QString("Desconocido"); // Si no se pudo resolver, devuelve "Desconocido"
}
