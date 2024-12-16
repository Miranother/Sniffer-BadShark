/********************************************************************************
** Form generated from reading UI file 'v1.ui'
**
** Created by: Qt User Interface Compiler version 6.8.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_V1_H
#define UI_V1_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_v1
{
public:
    QWidget *centralwidget;
    QLabel *label;
    QLabel *label_2;
    QLineEdit *LineEscoger;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *v1)
    {
        if (v1->objectName().isEmpty())
            v1->setObjectName("v1");
        v1->resize(800, 600);
        centralwidget = new QWidget(v1);
        centralwidget->setObjectName("centralwidget");
        label = new QLabel(centralwidget);
        label->setObjectName("label");
        label->setGeometry(QRect(20, -30, 271, 131));
        label_2 = new QLabel(centralwidget);
        label_2->setObjectName("label_2");
        label_2->setGeometry(QRect(30, 70, 63, 20));
        LineEscoger = new QLineEdit(centralwidget);
        LineEscoger->setObjectName("LineEscoger");
        LineEscoger->setGeometry(QRect(70, 70, 471, 28));
        v1->setCentralWidget(centralwidget);
        menubar = new QMenuBar(v1);
        menubar->setObjectName("menubar");
        menubar->setGeometry(QRect(0, 0, 800, 25));
        v1->setMenuBar(menubar);
        statusbar = new QStatusBar(v1);
        statusbar->setObjectName("statusbar");
        v1->setStatusBar(statusbar);

        retranslateUi(v1);

        QMetaObject::connectSlotsByName(v1);
    } // setupUi

    void retranslateUi(QMainWindow *v1)
    {
        v1->setWindowTitle(QCoreApplication::translate("v1", "v1", nullptr));
        label->setText(QCoreApplication::translate("v1", "<html><head/><body><p><span style=\" font-size:28pt; font-weight:700;\">BADSHARK</span></p></body></html>", nullptr));
        label_2->setText(QCoreApplication::translate("v1", "Filtro:", nullptr));
        LineEscoger->setPlaceholderText(QCoreApplication::translate("v1", "Escribe el filtro...", nullptr));
    } // retranslateUi

};

namespace Ui {
    class v1: public Ui_v1 {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_V1_H
