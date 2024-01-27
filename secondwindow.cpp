// secondwindow.cpp
#include "secondwindow.h"
#include <QDebug>
#include <QFileInfo>
#include <QMessageBox>
#include <QProcess>


SecondWindow::SecondWindow(QWidget *parent)
    : QWidget(parent)
{
    setWindowTitle("EncryptAES Configuration");

    // Set the application icon (logo)
    QIcon appIcon(":assets/Icons/logo.jpg"); // Adjust the path accordingly
    setWindowIcon(appIcon);

    // Set up layout for the second window using QGridLayout
    QGridLayout* secondWindowLayout = new QGridLayout(this);
    secondWindowLayout->setContentsMargins(2, 2, 2, 2); // Set smaller margins
    secondWindowLayout->setVerticalSpacing(10);   // Set vertical spacing between rows

    // Background Image
    QLabel* backgroundImage = new QLabel(this);
    QPixmap pixmap(":assets/Icons/walls.jpg");  // Adjust the path to your image
    backgroundImage->setPixmap(pixmap);
    backgroundImage->setScaledContents(true);

    // Add the background image to the layout
    secondWindowLayout->addWidget(backgroundImage, 0, 0, 4, 2); // Span across all rows and columns

    // Placeholder widget for centering
    QWidget* placeholderWidget = new QWidget(this);
    QGridLayout* placeholderLayout = new QGridLayout(placeholderWidget);
    placeholderWidget->setLayout(placeholderLayout);
    secondWindowLayout->addWidget(placeholderWidget, 2, 0, 1, 2); // Add margin from the top
    secondWindowLayout->setRowStretch(2, 1);  // Add stretch to push the buttons to the middle

    // Create components for the second window
    aesKeyLabel = new QLabel("AES256 Enc. Key", this);
    aesKeyLineEdit = new QLineEdit(this);
    aesKeyLineEdit->setFixedWidth(300);

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
    aesKeyLabel->setPalette(palette);
    filePathLabel->setPalette(palette);

    QFont boldFont;
    boldFont.setBold(true);
    boldFont.setPointSize(12);  // Increased font size
    aesKeyLabel->setFont(boldFont);
    filePathLabel->setFont(boldFont);

    // Set text color and font for the button
    palette.setColor(QPalette::ButtonText, Qt::white);
    browseButton->setPalette(palette);
    browseButton->setFont(boldFont);

    // Add components to the layout
    placeholderLayout->addWidget(aesKeyLabel, 0, 0);
    placeholderLayout->addWidget(aesKeyLineEdit, 0, 1);

    placeholderLayout->addWidget(filePathLabel, 1, 0);
    placeholderLayout->addWidget(filePathLineEdit, 1, 1);
    placeholderLayout->addWidget(browseButton, 1, 2, 1, 2); // Browse button takes remaining width

    browseButton->setFixedWidth(150);

    // Create "Finish" button
    finishButton = new QPushButton("EncryptAES", this);
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
    secondWindowLayout->addLayout(finishLayout, 3, 0, 1, 2);

    // Add vertical spacer for padding
    QSpacerItem* verticalSpacer = new QSpacerItem(20, 80, QSizePolicy::Minimum, QSizePolicy::Expanding);
    secondWindowLayout->addItem(verticalSpacer, 3, 0, 1, 2);

    // Set the layout for the second window
    setLayout(secondWindowLayout);

    // Set the fixed size of the window
    setFixedSize(500, 400); // Adjust the size as needed

    connect(browseButton, &QPushButton::clicked, this, &SecondWindow::browseFile);
    connect(finishButton, &QPushButton::clicked, this, &SecondWindow::finishClicked);
}

SecondWindow::~SecondWindow()
{
}

void SecondWindow::browseFile()
{
    // Update the member variable with the selected file path
    QString newSelectedFilePath = QFileDialog::getOpenFileName(this, "Select File", QDir::homePath(), "Text files (*.txt)");

    // Check if the user selected a file
    if (!newSelectedFilePath.isEmpty()) {
        selectedFilePath = newSelectedFilePath;
        filePathLineEdit->setText(selectedFilePath);
    }
}
void SecondWindow::finishClicked()
{
    // Check if both AES key and file path are entered
    if (aesKeyLineEdit->text().isEmpty() || selectedFilePath.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please enter AES256 key and select a file.");
        return;
    }

    // Perform the finish action using aesKeyLineEdit->text() and selectedFilePath
    // For now, let's print a message
    qDebug() << "AES Key: " << aesKeyLineEdit->text();
    qDebug() << "File Path: " << selectedFilePath;

    // Call the encrypt function
    encrypt(selectedFilePath, aesKeyLineEdit->text());


    // Optionally, you can close the SecondWindow
    // close();
}

void SecondWindow::encrypt(const QString& inFile, const QString& key)
{
    QFileInfo fileInfo(inFile);
    QString outputPath = fileInfo.path() + "/file.enc";
    QString command = "openssl enc -aes-256-cbc -salt -pbkdf2 -in \"" + inFile + "\" -out \"" + outputPath + "\" -k \"" + key + "\"";

    // Run the command using QProcess
    QProcess process;
    process.start(command);
    process.waitForFinished();

    if (process.exitCode() == 0) {
        // Encryption succeeded
        QString message = "Encryption is successful.\nOutput file: " + outputPath;
        QMessageBox::information(this, "Encryption Success", message);
    } else {
        // Encryption failed
        QString errorMessage = "Encryption failed. Please check your input and try again.";
        QMessageBox::critical(this, "Encryption Error", errorMessage);
    }
}


