// sixthwindow.h
#ifndef SIXTHWINDOW_H
#define SIXTHWINDOW_H

#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QGridLayout>
#include <QFileDialog>

class SixthWindow : public QWidget
{
    Q_OBJECT

public:
    SixthWindow(QWidget *parent = nullptr);
    ~SixthWindow();
    void encryptAndSign(const QString& inFile, const QString& key);

private:
    QLabel* aesKeyLabel;
    QLineEdit* aesKeyLineEdit;
    QLabel* filePathLabel;
    QLineEdit* filePathLineEdit;
    QPushButton* browseButton;
    QPushButton* encryptAndSignButton;
    QString selectedFilePath;

private slots:
    void browseFile();
    void encryptAndSignClicked();
};

#endif // SIXTHWINDOW_H
