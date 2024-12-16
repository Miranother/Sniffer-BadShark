#ifndef V1_H
#define V1_H

#include <QMainWindow>
#include <pcap/pcap.h>
#include <QPushButton>
#include <QLineEdit>
#include <QString>          // Para trabajar con cadenas
#include <QFile>            // Para trabajar con archivos
#include <QTextStream>      // Para escribir en el archivo
#include <QDir>             // Para trabajar con directorios
#include <QMessageBox>      // Para mostrar cuadros de mensaje

namespace Ui {
class v1;
}

class v1 : public QMainWindow
{
    Q_OBJECT

public:
    explicit v1(QWidget *parent = nullptr);  // Constructor
    ~v1();  // Destructor

private:
    Ui::v1 *ui;  // Puntero a la interfaz de usuario generada automáticamente
    pcap_if_t *selected_device = nullptr;  // Almacena el dispositivo seleccionado

    // Funciones para obtener dispositivos y seleccionar uno
    void obtenerDispositivosDeRed();
    void seleccionarDispositivo(pcap_if_t *device, int dispositivoIndex);

    // Función para guardar los dispositivos en un archivo de texto
    void guardarDispositivosEnArchivo(pcap_if_t *all_devices);

    // Función para limpiar el nombre del dispositivo (opcional)
    QString limpiarNombreDispositivo(const QString &deviceName);
    void crearBotonesDesdeArchivo();
    void cargarFuente();
    void paintEvent(QPaintEvent *event);
    void reiniciarInterfaz();
    void limpiarPestania();
    void filtrarTexto();

    bool validarDominio(const QString &dominio);
    QString resolverDominio(const QString &dominio);
signals:
    void ventanaTerminada();
};

#endif // V1_H
