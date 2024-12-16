#include "v1.h"
#include "./ui_v1.h"
#include "almacenartarjeta.h"  // Incluir la clase para gestionar el dispositivo seleccionado
#include <pcap/pcap.h>
#include <QMessageBox>
#include <QFile>
#include <QTextStream>
#include <QDir>
#include <QDebug>
#include <QVBoxLayout>
#include <QFontDatabase>
#include <QPainter>
#include <QLinearGradient>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

v1::v1(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::v1)

{
    ui->setupUi(this);
    setWindowTitle("BadShark - Ventana Principal");
    setFixedSize(1080, 720);
    setWindowIcon(QIcon("./BadShark.png"));

    cargarFuente();
    obtenerDispositivosDeRed();
}

v1::~v1()
{
    emit ventanaTerminada();
    delete ui;
}

void v1::obtenerDispositivosDeRed()
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_devices, *device;

    int result = pcap_findalldevs(&all_devices, error_buffer);
    if (result == -1) {
        QMessageBox::critical(this, "Error", QString("Error encontrando dispositivos: %1").arg(error_buffer));
        return;
    }

    if (all_devices == nullptr) {
        QMessageBox::information(this, "Sin dispositivos", "No se encontraron dispositivos de red.");
        return;
    }

    guardarDispositivosEnArchivo(all_devices);

    pcap_freealldevs(all_devices);
    crearBotonesDesdeArchivo();
}

void v1::guardarDispositivosEnArchivo(pcap_if_t *all_devices)
{
    QFile file("./dispositivos_red.txt");
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qDebug() << "Error al abrir el archivo para escribir.";
        return;
    }

    QTextStream out(&file);

    pcap_if_t *device;
    int dispositivoIndex = 1;

    for (device = all_devices; device != NULL; device = device->next, dispositivoIndex++) {
        QString deviceName = QString::fromLocal8Bit(device->name ? device->name : "");
        QString deviceDescription = (device->description != nullptr)
                                        ? QString::fromLocal8Bit(device->description)
                                        : "Sin descripción";

        out << deviceDescription << " | " << deviceName << "\n";
    }

    file.close();
    qDebug() << "Dispositivos guardados en dispositivos_red.txt";
}

void v1::crearBotonesDesdeArchivo()
{
    QFile file("./dispositivos_red.txt");

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "No se pudo abrir el archivo de dispositivos.");
        return;
    }

    QVBoxLayout *layout = new QVBoxLayout();
    layout->setSpacing(5);
    layout->setAlignment(Qt::AlignCenter);
    layout->setContentsMargins(5, 5, 5, 5);

    QTextStream in(&file);
    QString line;

    // Crear etiquetas estáticas
    QLabel *labelBadShark = new QLabel("BADSHARK", this);
    QFont fontBadShark("C rial black", 50, QFont::Bold);
    labelBadShark->setFont(fontBadShark);
    labelBadShark->resize(400, 150);
    labelBadShark->move(0, -30);
    labelBadShark->show();

    QLabel *labelFiltro = new QLabel("Filtro:", this);
    QFont fontfiltro("Arial", 15, QFont::Bold);
    labelFiltro->setFont(fontfiltro);
    labelFiltro->resize(400, 100);
    labelFiltro->move(0, 45);
    labelFiltro->show();

    QLineEdit *lineEditFiltro = new QLineEdit(this);
    lineEditFiltro->setPlaceholderText("Escriba su filtro...");
    QFont font("Arial", 10, QFont::Bold);
    lineEditFiltro->setFont(font);
    lineEditFiltro->move(55, 80);
    lineEditFiltro->resize(400, 30);
    lineEditFiltro->show();
    connect(lineEditFiltro, &QLineEdit::returnPressed, this, &v1::filtrarTexto);

    QLabel *labelNombres = new QLabel("Carlos Enrique Blanco Ortiz   ID:349388\nAlan Gael Gallardo Jimenez    ID:351914\nCinthia Edith García de Luna  ID:347823 \nAlondra Lizbeth Ibarra Chavez ID:347921 \nJosé de Jesus Torrez Montero ID:290400", this);
    QFont fontnombres("Arial", 10, QFont::Bold);
    labelNombres->setFont(fontnombres);
    labelNombres->resize(400, 150);  // Ajustar el tamaño manualmente si es necesario
    labelNombres->move(700, 50);  // Mover manualmente el labelFiltro a la izquierda
    labelNombres->show();




    // Leer y procesar cada línea del archivo
    while (!in.atEnd()) {
        line = in.readLine();
        QStringList parts = line.split(" | ");

        if (parts.size() == 2) {
            QString descripcion = parts[0].trimmed();
            QString nombre = parts[1].trimmed();

            QPushButton *button = new QPushButton(descripcion);
            button->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
            button->setMinimumHeight(35);

            // Conectar el botón para almacenar el dispositivo seleccionado
            connect(button, &QPushButton::clicked, this, [this, descripcion, nombre]() {
                // Guardar el dispositivo seleccionado
                limpiarPestania();
                DispositivoSeleccionado::setDispositivo(descripcion, nombre);
                qDebug() << "Dispositivo seleccionado:";
                qDebug() << "Descripción:" << DispositivoSeleccionado::getDescripcion();
                qDebug() << "Nombre:" << DispositivoSeleccionado::getNombre();
                QMessageBox::information(this, "Dispositivo Seleccionado", "Has seleccionado: " + nombre);
                emit ventanaTerminada();
            });

            layout->addWidget(button);
        }
    }

    file.close();

    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->addLayout(layout);

    setCentralWidget(centralWidget);
}



void v1::paintEvent(QPaintEvent *event)
{
    QMainWindow::paintEvent(event);

    QPainter painter(this);
    QRadialGradient radialGradient(width() / 2, height() / 2, width() / 2);
    radialGradient.setColorAt(0, QColor(255, 255, 255));
    radialGradient.setColorAt(1, QColor(0, 0, 0));
    painter.setBrush(radialGradient);
    painter.setPen(Qt::NoPen);
    painter.drawRect(0, 0, width(), height());
}


void v1::cargarFuente()
{
    QString fontPath = "./CRBLATRIAL.ttf";
    int fontId = QFontDatabase::addApplicationFont(fontPath);
    if (fontId == -1) {
        QMessageBox::warning(this, "Fuente no encontrada", "No se pudo cargar la fuente personalizada.");
        return;
    }

    QString fontFamily = QFontDatabase::applicationFontFamilies(fontId).at(0);
    qDebug() << "Fuente cargada exitosamente: " << fontFamily;
}

void v1::limpiarPestania()
{
    // Limpiar la UI actual
    QList<QPushButton *> buttons = findChildren<QPushButton *>();
    for (QPushButton *button : buttons) {
        delete button;  // Eliminar botones
    }

    QList<QLabel *> labels = findChildren<QLabel *>();
    for (QLabel *label : labels) {
        delete label;
    }

    QList<QLineEdit *> lineEdits = findChildren<QLineEdit *>();
    for (QLineEdit *lineEdit : lineEdits) {
        delete lineEdit;
    }
}


void v1::filtrarTexto()
{
    QLineEdit* lineEditFiltro = findChild<QLineEdit*>(); // Buscar el QLineEdit en la UI
    if (lineEditFiltro) {
        QString textoFiltro = lineEditFiltro->text();
        if (textoFiltro.isEmpty()) {
            return;
        }

        // Validar el texto ingresado para "none"
        if (textoFiltro.toLower() == "none") {
            // Eliminar los filtros
            QFile file("./filtro.txt");
            if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                file.resize(0); // Limpiar el contenido del archivo
                file.close();
                qDebug() << "Filtros eliminados de filtro.txt";
                QMessageBox::information(this, "Filtros eliminados", "Se han eliminado los filtros.");
            } else {
                qDebug() << "Error al abrir el archivo para escribir.";
            }
            lineEditFiltro->clear(); // Limpiar el QLineEdit
            return; // Salir de la función
        }

        // Validar el texto ingresado para ICMP, UDP, TCP
        if (textoFiltro.toLower().contains("icmp") || textoFiltro.toLower().contains("udp") || textoFiltro.toLower().contains("tcp")) {
            // Guardar el texto válido en el archivo
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
            QString dominio = textoFiltro.mid(5).trimmed(); // Extrae el dominio del filtro y elimina espacios

            // Validar el dominio usando la función validarDominio
            if (validarDominio(dominio)) {
                // Dominio existe, guardar el texto válido en el archivo
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
            } else {
                // Dominio no existe, mostrar mensaje de error
                QMessageBox::critical(this, "Error", "El dominio " + dominio + " no existe.");
                lineEditFiltro->clear(); // Limpiar el QLineEdit
            }
        } else {
            QMessageBox::warning(this, "Filtro no válido", "El filtro ingresado no es válido. Por favor, ingrese un filtro que contenga ICMP, UDP, TCP o host:");
            lineEditFiltro->clear(); // Limpiar el QLineEdit
        }
    }
}


bool v1::validarDominio(const QString &dominio)
{
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        QMessageBox::critical(this, "Error", "No se pudo inicializar Winsock.");
        return false;
    }
    struct hostent *he = gethostbyname(dominio.toStdString().c_str());
    WSACleanup();
    return he != NULL;
}

QString v1::resolverDominio(const QString &dominio) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return QString(); // Error al inicializar Winsock
    }

    struct hostent *he = gethostbyname(dominio.toStdString().c_str());
    WSACleanup();

    if (he == nullptr) {
        return QString(); // No se pudo resolver el dominio
    }

    // Convertir la dirección IP a un QString
    struct in_addr addr;
    memcpy(&addr, he->h_addr_list[0], sizeof(struct in_addr));
    return QString(inet_ntoa(addr)); // Devuelve la dirección IP como QString
}
