// thirdwindow.cpp
#include "thirdwindow.h"
#include <QDebug>
#include <QFileInfo>
#include <QMessageBox>
#include <QProcess>


ThirdWindow::ThirdWindow(QWidget *parent)
    : QWidget(parent)
{
    setWindowTitle("DecryptAES Configuration");

    // Set the application icon (logo)
    QIcon appIcon(":assets/Icons/logo.jpg"); // Adjust the path accordingly
    setWindowIcon(appIcon);

    // Set up layout for the third window using QGridLayout
    QGridLayout* thirdWindowLayout = new QGridLayout(this);
    thirdWindowLayout->setContentsMargins(2, 2, 2, 2); // Set smaller margins
    thirdWindowLayout->setVerticalSpacing(10);   // Set vertical spacing between rows

    // Background Image
    QLabel* backgroundImage = new QLabel(this);
    QPixmap pixmap(":assets/Icons/walls.jpg");  // Adjust the path to your image
    backgroundImage->setPixmap(pixmap);
    backgroundImage->setScaledContents(true);

    // Add the background image to the layout
    thirdWindowLayout->addWidget(backgroundImage, 0, 0, 4, 2); // Span across all rows and columns

    // Placeholder widget for centering
    QWidget* placeholderWidget = new QWidget(this);
    QGridLayout* placeholderLayout = new QGridLayout(placeholderWidget);
    placeholderWidget->setLayout(placeholderLayout);
    thirdWindowLayout->addWidget(placeholderWidget, 2, 0, 1, 2); // Add margin from the top
    thirdWindowLayout->setRowStretch(2, 1);  // Add stretch to push the buttons to the middle

    // Create components for the third window
    aesKeyLabel = new QLabel("AES256 Dec. Key", this);
    aesKeyLineEdit = new QLineEdit(this);
    aesKeyLineEdit->setFixedWidth(300);

    filePathLabel = new QLabel("Cipher text file path", this);
    filePathLineEdit = new QLineEdit(this);

    // Set maximum width for the file path QLineEdit
    filePathLineEdit->setMaximumWidth(200);  // Adjust the width as needed

    browseButton = new QPushButton("Browse Cipher Text", this);
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
    finishButton = new QPushButton("DecryptAES", this);
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
    thirdWindowLayout->addLayout(finishLayout, 3, 0, 1, 2);

    // Add vertical spacer for padding
    QSpacerItem* verticalSpacer = new QSpacerItem(20, 80, QSizePolicy::Minimum, QSizePolicy::Expanding);
    thirdWindowLayout->addItem(verticalSpacer, 3, 0, 1, 2);

    // Set the layout for the third window
    setLayout(thirdWindowLayout);

    // Set the fixed size of the window
    setFixedSize(500, 400); // Adjust the size as needed

    connect(browseButton, &QPushButton::clicked, this, &ThirdWindow::browseFile);
    connect(finishButton, &QPushButton::clicked, this, &ThirdWindow::finishClicked);
}

ThirdWindow::~ThirdWindow()
{
}

void ThirdWindow::browseFile()
{
    // Update the member variable with the selected file path
    selectedFilePath = QFileDialog::getOpenFileName(this, "Select File", QDir::homePath(), "Encrypted files (*.enc)");
    filePathLineEdit->setText(selectedFilePath);
}

void ThirdWindow::finishClicked()
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

    // Call the decrypt function
    decrypt(selectedFilePath, aesKeyLineEdit->text());


    // Optionally, you can close the ThirdWindow
    // close();
}

void ThirdWindow::decrypt(const QString& inFile, const QString& key)
{
    QFileInfo fileInfo(inFile);
    QString outputPath = fileInfo.path() + "/decrypted_file.txt";  // Adjust the output file name as needed
    QString command = "openssl enc -aes-256-cbc -d -pbkdf2 -in \"" + inFile + "\" -out \"" + outputPath + "\" -k \"" + key + "\"";

    // Run the command using QProcess
    QProcess process;
    process.start(command);
    process.waitForFinished();

    if (process.exitCode() == 0) {
        // Decryption succeeded
        QString message = "Decryption is successful.\nOutput file: " + outputPath;
        QMessageBox::information(this, "Decryption Success", message);
    } else {
        // Decryption failed
        QString errorMessage = "Decryption failed. Please check your input and try again.";
        QMessageBox::critical(this, "Decryption Error", errorMessage);
    }
}
