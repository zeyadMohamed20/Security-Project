// fifthwindow.h
// fifthwindow.h
#ifndef FIFTHWINDOW_H
#define FIFTHWINDOW_H

#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QGridLayout>
#include <QFileDialog>

class FifthWindow : public QWidget
{
    Q_OBJECT

public:
    FifthWindow(QWidget *parent = nullptr);
    ~FifthWindow();
    void verify(const QString& plainTextFile, const QString& sigFile);

private:
    QLabel* plainFilePathLabel;
    QLineEdit* plainFilePathLineEdit;
    QPushButton* browsePlainTextButton;

    QLabel* sigFilePathLabel;
    QLineEdit* sigFilePathLineEdit;
    QPushButton* browseSigButton;

    QPushButton* verifyButton;

    // Add member variables to store the selected file paths
    QString selectedPlainTextFilePath;
    QString selectedSigFilePath;

private slots:
    void browsePlainTextFile();
    void browseSigFile();
    void verifyClicked();
};

#endif // FIFTHWINDOW_H
