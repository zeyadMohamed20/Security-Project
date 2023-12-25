// mainwindow.h

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QGridLayout>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QFileDialog>
#include "secondwindow.h"
#include "thirdwindow.h"
#include "fourthwindow.h"
#include "fifthwindow.h"
#include "sixthwindow.h"
#include "seventhwindow.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void resizeEvent(QResizeEvent *event) override;

signals:
        void resized();

private slots:
    void encryptAESClicked();
    void decryptAESClicked();
    void signClicked();
    void verifyClicked();
    void encryptAndSignClicked();
    void decryptAndVerifyClicked();

private:
    void adjustButtonSize();
    SecondWindow* secondWindow; // Change the type to the second window
    ThirdWindow*  thirdWindow; // Change the type to the third window
    FourthWindow*  fourthWindow; // Change the type to the fourth window
    FifthWindow*  fifthWindow; // Change the type to the fifth window
    SixthWindow*  sixthWindow; // Change the type to the sixth window
    SeventhWindow*  seventhWindow; // Change the type to the seventh window
    QLabel *backgroundImage;
};

#endif // MAINWINDOW_H
