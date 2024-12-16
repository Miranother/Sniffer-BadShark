#include "almacenartarjeta.h"

// Inicializamos las variables estáticas
QString DispositivoSeleccionado::descripcion = "";
QString DispositivoSeleccionado::nombre = "";

void DispositivoSeleccionado::setDispositivo(const QString &desc, const QString &nom)
{
    descripcion = desc;
    nombre = nom;
}

QString DispositivoSeleccionado::getDescripcion()
{
    return descripcion;
}

QString DispositivoSeleccionado::getNombre()
{
    return nombre;
}


