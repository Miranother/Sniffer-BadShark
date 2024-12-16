#include "v1.h"
#include "capturarpaquetes.h"

#include <QApplication>
#include <QLocale>
#include <QTranslator>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    #include <QDebug>
    qDebug() << "Depuración: el programa ha comenzado a ejecutarse";

    QTranslator translator;
    const QStringList uiLanguages = QLocale::system().uiLanguages();
    for (const QString &locale : uiLanguages) {
        const QString baseName = "BadShark_" + QLocale(locale).name();
        if (translator.load(":/i18n/" + baseName)) {
            a.installTranslator(&translator);
            break;
        }
    }

    v1 ventanaV1;

    // Conectar la señal para abrir capturarpaquetes
    QObject::connect(&ventanaV1, &v1::ventanaTerminada, [&]() {
        capturarpaquetes *ventanaCapturarPaquetes = new capturarpaquetes();
        ventanaCapturarPaquetes->show();
        ventanaV1.close();  // Cerrar la ventana actual (opcional)
    });

    ventanaV1.show();

    return a.exec();
}
