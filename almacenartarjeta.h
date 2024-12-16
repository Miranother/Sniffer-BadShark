#ifndef ALMACENARTARJETA_H
#define ALMACENARTARJETA_H

#include <QString>

class DispositivoSeleccionado
{
public:
    // Métodos estáticos para gestionar el dispositivo seleccionado
    static void setDispositivo(const QString &descripcion, const QString &nombre);
    static QString getDescripcion();
    static QString getNombre();

private:
    static QString descripcion;
    static QString nombre;
};

#endif // ALMACENARTARJETA_H
