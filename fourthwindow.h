// fourthwindow.h
// fourthwindow.h
#ifndef FOURTHWINDOW_H
#define FOURTHWINDOW_H

#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QGridLayout>
#include <QFileDialog>

class FourthWindow : public QWidget
{
    Q_OBJECT

public:
    FourthWindow(QWidget *parent = nullptr);
    ~FourthWindow();
    void sign(const QString& inFile);
    void generateKey(const QString& inFile);

private:
    QLabel* filePathLabel;
    QLineEdit* filePathLineEdit;
    QPushButton* browseButton;
    QPushButton* finishButton;
    // Add a member variable to store the selected file path
    QString selectedFilePath;

private slots:
    void browseFile();
    void finishClicked();
};

#endif // FOURTHWINDOW_H
