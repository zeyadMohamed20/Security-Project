// fourthwindow.cpp
#include "fourthwindow.h"
#include <QDebug>
#include <QFileInfo>
#include <QMessageBox>
#include <QProcess>

// fourthwindow.cpp
#include "fourthwindow.h"
#include <QDebug>
#include <QFileInfo>
#include <QMessageBox>
#include <QProcess>

FourthWindow::FourthWindow(QWidget *parent)
    : QWidget(parent)
{
    setWindowTitle("Sign Configuration");

    // Set the application icon (logo)
    QIcon appIcon(":assets/Icons/logo.jpg"); // Adjust the path accordingly
    setWindowIcon(appIcon);

    // Set up layout for the fourth window using QGridLayout
    QGridLayout* fourthWindowLayout = new QGridLayout(this);
    fourthWindowLayout->setContentsMargins(2, 2, 2, 2); // Set smaller margins
    fourthWindowLayout->setVerticalSpacing(10);   // Set vertical spacing between rows

    // Background Image
    QLabel* backgroundImage = new QLabel(this);
    QPixmap pixmap(":assets/Icons/walls.jpg");  // Adjust the path to your image
    backgroundImage->setPixmap(pixmap);
    backgroundImage->setScaledContents(true);

    // Add the background image to the layout
    fourthWindowLayout->addWidget(backgroundImage, 0, 0, 4, 2); // Span across all rows and columns

    // Placeholder widget for centering
    QWidget* placeholderWidget = new QWidget(this);
    QGridLayout* placeholderLayout = new QGridLayout(placeholderWidget);
    placeholderWidget->setLayout(placeholderLayout);
    fourthWindowLayout->addWidget(placeholderWidget, 2, 0, 1, 2); // Add margin from the top
    fourthWindowLayout->setRowStretch(2, 1);  // Add stretch to push the buttons to the middle

    // Create components for the fourth window
    filePathLabel = new QLabel("Plain text file path", this);
    filePathLineEdit = new QLineEdit(this);

    // Set maximum width for the file path QLineEdit
    filePathLineEdit->setMaximumWidth(200);  // Adjust the width as needed

    browseButton = new QPushButton("Browse Plain Text", this);
    browseButton->setStyleSheet("QPushButton {"
                                "    background-color: rgb(139, 0, 0);"
                                "    border-radius: 10px;"
                                "    text-align: center;"
                                "    color: white;"
                                "    font-weight: bold;"
                                "}"
                                "QPushButton:hover {"
                                "    background-color: rgb(100, 0, 0);"
                                "}");

    // Set text color and font for labels
    QPalette palette;
    palette.setColor(QPalette::WindowText, Qt::white);
    filePathLabel->setPalette(palette);

    QFont boldFont;
    boldFont.setBold(true);
    boldFont.setPointSize(12);  // Increased font size
    filePathLabel->setFont(boldFont);

    // Set text color and font for the button
    palette.setColor(QPalette::ButtonText, Qt::white);
    browseButton->setPalette(palette);
    browseButton->setFont(boldFont);

    // Add components to the layout
    placeholderLayout->addWidget(filePathLabel, 0, 0);
    placeholderLayout->addWidget(filePathLineEdit, 0, 1);
    placeholderLayout->addWidget(browseButton, 0, 2, 1, 2); // Browse button takes remaining width

    browseButton->setFixedWidth(150);

    // Create "Finish" button
    finishButton = new QPushButton("Sign", this);
    finishButton->setStyleSheet("QPushButton {"
                                "    background-color: rgb(0, 128, 0);" // Green color
                                "    border-radius: 10px;"
                                "    text-align: center;"
                                "    color: white;"
                                "    font-weight: bold;"
                                "}"
                                "QPushButton:hover {"
                                "    background-color: rgb(0, 100, 0);" // Darker green on hover
                                "}");

    // Set text color and font for the "Finish" button
    finishButton->setPalette(palette);
    finishButton->setFont(boldFont);
    finishButton->setFixedWidth(300);

    // Create a horizontal layout for the "Finish" button
    QHBoxLayout* finishLayout = new QHBoxLayout();
    finishLayout->addWidget(finishButton);

    // Add the "Finish" button to the layout
    fourthWindowLayout->addLayout(finishLayout, 3, 0, 1, 2); // Placed in the row below

    // Add vertical spacer for padding
    QSpacerItem* verticalSpacer = new QSpacerItem(20, 80, QSizePolicy::Minimum, QSizePolicy::Expanding);
    fourthWindowLayout->addItem(verticalSpacer, 3, 0, 1, 2); // Placed in the row below

    // Set the layout for the fourth window
    setLayout(fourthWindowLayout);

    // Set the fixed size of the window
    setFixedSize(500, 400); // Adjust the size as needed

    connect(browseButton, &QPushButton::clicked, this, &FourthWindow::browseFile);
    connect(finishButton, &QPushButton::clicked, this, &FourthWindow::finishClicked);
}

FourthWindow::~FourthWindow()
{
}

void FourthWindow::browseFile()
{
    // Update the member variable with the selected file path
    selectedFilePath = QFileDialog::getOpenFileName(this, "Select File", QDir::homePath(), "Text files (*.txt)");
    filePathLineEdit->setText(selectedFilePath);
}

void FourthWindow::finishClicked()
{
    // Check if the file path is entered
    if (selectedFilePath.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please select a file.");
        return;
    }

    // Perform the finish action using selectedFilePath
    // For now, let's print a message
    qDebug() << "File Path: " << selectedFilePath;

    generateKey(selectedFilePath);
    // Call the sign function
    sign(selectedFilePath);

    // Optionally, you can close the FourthWindow
    // close();
}

void FourthWindow::sign(const QString& inFile)
{
    QFileInfo fileInfo(inFile);
    QString signaturePath = fileInfo.path() + "/signature.sig";  // Adjust the signature file name as needed

    // Adjust the paths for the private key and public key
    QString privateKeyPath = fileInfo.path() + "/private.pem";
    QString publicKeyPath = fileInfo.path() + "/public.pem";

    // Construct the command
    QString command = "openssl pkeyutl -sign -in \"" + inFile + "\" -out \"" + signaturePath + "\" -inkey \"" + privateKeyPath + "\"";

    // Run the command using QProcess
    QProcess process;
    process.start(command);
    process.waitForFinished();

    if (process.exitCode() == 0) {
        // Sign succeeded
        QString message = "Sign is successful.\nSignature file: " + signaturePath;
        QMessageBox::information(this, "Sign Success", message);
    } else {
        // Sign failed
        QString errorMessage = "Sign failed. Please check your input and try again.";
        QMessageBox::critical(this, "Sign Error", errorMessage);
    }
}



void FourthWindow::generateKey(const QString& inFile)
{
    QFileInfo fileInfo(inFile);
    QString outputPrivatePath = fileInfo.path() + "/private.pem";  // Adjust the output file name as needed

    // Generate RSA private key
    QString privateKeyCommand = "openssl genpkey -algorithm RSA -out \"" + outputPrivatePath + "\"";
    QProcess privateKeyProcess;
    privateKeyProcess.start(privateKeyCommand);
    privateKeyProcess.waitForFinished();

    if (privateKeyProcess.exitCode() != 0) {
        qDebug() << "Error generating private key.";
        return;
    }

    // Generate RSA public key
    QString outputPublicPath = fileInfo.path() + "/public.pem";
    QString publicKeyCommand = "openssl rsa -pubout -in \"" + outputPrivatePath + "\" -out \"" + outputPublicPath + "\"";
    QProcess publicKeyProcess;
    publicKeyProcess.start(publicKeyCommand);
    publicKeyProcess.waitForFinished();

    if (publicKeyProcess.exitCode() != 0) {
        qDebug() << "Error generating public key.";
        return;
    }

    qDebug() << "Key generation successful.";
}

