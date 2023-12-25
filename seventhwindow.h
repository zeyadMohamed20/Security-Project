#ifndef SEVENTHWINDOW_H
#define SEVENTHWINDOW_H

#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QGridLayout>
#include <QFileDialog>

class SeventhWindow : public QWidget
{
    Q_OBJECT

public:
    SeventhWindow(QWidget *parent = nullptr);
    ~SeventhWindow();
    void decryptAndVerify(const QString &inFile, const QString &key, const QString &sigFile);

private:
    QLabel *aesKeyLabel;
    QLineEdit *aesKeyLineEdit;
    QLabel *filePathLabel;
    QLineEdit *filePathLineEdit;
    QLabel *sigFilePathLabel;
    QLineEdit *sigFilePathLineEdit;
    QPushButton *browseButton;
    QPushButton *browseSigButton;
    QPushButton *encryptAndSignButton;
    QString selectedFilePath;

private slots:
    void browseFile();
    void browseSigFile();
    void decryptAndVerifyClicked();
};

#endif // SEVENTHWINDOW_H
