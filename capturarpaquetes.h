#ifndef CAPTURARPAQUETES_H
#define CAPTURARPAQUETES_H

#include <QMainWindow>
#include <pcap/pcap.h>
#include <QTableWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QList>
#include <QTextEdit>
#include <QTime>
#include <QMap>
#include <QMutex>

struct Paquete {
    int frameNumber; // Número de frame
    int frameLength; // Longitud del frame
    QString interfaceName; // Nombre de la interfaz
    QString arrivalTime; // Hora de llegada
    QString utcArrivalTime; // Hora de llegada en UTC
    long epochArrivalTime; // Tiempo en epoch
    QString elapsedTime; // Nuevo campo para el tiempo transcurrido
    QString encapsulationType; // Tipo de encapsulación
    QString srcMac; // Dirección MAC de origen
    QString dstMac; // Dirección MAC de destino
    QString ethType; // Tipo de Ethernet
    QString srcIP; // Dirección IP de origen
    QString dstIP; // Dirección IP de destino
    QString ipVersion; // Versión de IP
    QString ipHeaderLength; // Longitud del encabezado IP
    QString totalLength; // Longitud total del paquete IP
    QString identification; // Identificación del paquete IP
    QString flags; // Flags del paquete IP
    QString fragmentOffset; // Offset de fragmento
    QString ttl; // Tiempo de vida (TTL)
    QString protocol; // Protocolo (TCP, UDP, ICMP, etc.)
    QString headerChecksum; // Checksum del encabezado IP

    // Campos para TCP
    QString tcpSrcPort; // Puerto de origen TCP
    QString tcpDstPort; // Puerto de destino TCP
    QString tcpSeqNumber; // Número de secuencia TCP
    QString tcpAckNumber; // Número de acuse de recibo TCP
    QString tcpFlags; // Flags TCP
    QString tcpWindowSize; // Tamaño de la ventana TCP
    QString tcpChecksum; // Checksum TCP
    QString tcpUrgentPointer; // Puntero urgente TCP

    // Campos para UDP
    QString udpLength; // Longitud del paquete UDP
    QString udpChecksum; // Checksum del paquete UDP

    // Campos para ICMP
    QString icmpType; // Tipo de mensaje ICMP
    QString icmpCode; // Código del mensaje ICMP
    QString icmpChecksum; // Checksum del paquete ICMP
    QString icmpId; // Identificación del paquete ICMP
    QString icmpSequence; // Número de secuencia del paquete ICMP

    // Información de la carga útil
    QString payloadLength; // Longitud de la carga útil
    QString payloadData; // Datos de la carga útil
    QString sourceDeviceName; //Nombre del dispositivo
};
namespace Ui {
class capturarpaquetes;
}

class capturarpaquetes : public QMainWindow
{
    Q_OBJECT

public:
    explicit capturarpaquetes(QWidget *parent = nullptr);
    ~capturarpaquetes();
    QString dominio;
private:
    static QMap<QString, QString> cache; // Caché para almacenar resultados
    static QMutex cacheMutex;
    Ui::capturarpaquetes *ui;     // UI generada por Qt
    QTableWidget *tableWidget;    // Tabla para mostrar los paquetes capturados
    QPushButton *pauseButton;     // Botón de pausa/reanudar
    QLineEdit *filterLineEdit;    // Campo de texto para filtros
    bool paused;                  // Bandera para controlar la pausa
    QWidget *detailsWidget; // Declarar el widget de detalles
    QWidget *dissectorWidget; // Declarar el widget de disector
    int filaSeleccionada = -1;
    QTextEdit *detailsTextEdit;
    QTextEdit *dissectorTextEdit;
    QList<Paquete> paquetesCapturados;
    QTime startTime; // Para almacenar el tiempo de inicio
    // Función para iniciar la captura de paquetes
    void iniciarCaptura(const QString &deviceName);
    // Función para procesar un paquete capturado
    void procesarPaquete(const struct pcap_pkthdr *header, const u_char *packet);
    // Función para alternar el estado de pausa/reanudar
    void togglePause();
    bool procesarFiltroArchivo(const u_char *packet, const QString &filtro);
    bool procesarFiltroUsuario(const u_char *packet, const QString &filtro);
    void actualizarFiltro();
    void agregarPaqueteATabla(const struct timeval &timestamp, const QString &source, const QString &destination, const QString &protocol, int size, const QString &elapsedTime);
    void procesarFiltro();
    void filtrarHost(const QString &host);
    bool validarDominio(const QString &dominio);
    QString resolverDominio(const QString &dominio);
    bool procesarFiltroHost(const u_char *packet, const QString &dominio);
    void mostrarDetallesPaquete(QTableWidgetItem *item);
    QString obtenerDetallesDelPaquete(int fila);
    void guardarPaqueteEnArchivo(const Paquete &paquete);
    QString convertirAHexadecimal(const QByteArray &data);
    void guardarPaquetesEnCSV();
    void actualizarSeleccion();
    void guardarPaquetesEnXLSX();
    // QString resolverNombreDispositivo(const QString &ip);
    static void inicializarWinsock();
    static void limpiarWinsock();
    static QString resolverNombreDispositivo(const QString &ip);
};

#endif // CAPTURARPAQUETES_H
