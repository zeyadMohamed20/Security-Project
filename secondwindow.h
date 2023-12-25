// secondwindow.h
#ifndef SECONDWINDOW_H
#define SECONDWINDOW_H

#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QGridLayout>
#include <QFileDialog>

class SecondWindow : public QWidget
{
    Q_OBJECT

public:
    SecondWindow(QWidget *parent = nullptr);
    ~SecondWindow();
    void encrypt(const QString& inFile, const QString& key);

private:
    QLabel* filePathLabel;
    QLineEdit* filePathLineEdit;
    QPushButton* browseButton;
    QLabel* aesKeyLabel;
    QLineEdit* aesKeyLineEdit;
    QPushButton* finishButton;
    // Add a member variable to store the selected file path
    QString selectedFilePath;

private slots:
    void browseFile();
    void finishClicked();
};

#endif // SECONDWINDOW_H
