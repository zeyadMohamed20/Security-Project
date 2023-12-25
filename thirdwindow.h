// thirdwindow.h
#ifndef THIRDWINDOW_H
#define THIRDWINDOW_H

#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QGridLayout>
#include <QFileDialog>

class ThirdWindow : public QWidget
{
    Q_OBJECT

public:
    ThirdWindow(QWidget *parent = nullptr);
    ~ThirdWindow();
    void decrypt(const QString& inFile, const QString& key);

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

#endif // THIRDWINDOW_H
