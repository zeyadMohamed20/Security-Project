// sixthwindow.cpp
#include "sixthwindow.h"
#include "secondwindow.h"
#include "fourthwindow.h"
#include <QDebug>
#include <QFileInfo>
#include <QMessageBox>
#include <QProcess>

SixthWindow::SixthWindow(QWidget *parent)
    : QWidget(parent)
{
    setWindowTitle("Encrypt & Sign Configuration");

    // Set the application icon (logo)
    QIcon appIcon(":assets/Icons/logo.jpg"); // Adjust the path accordingly
    setWindowIcon(appIcon);

    // Set up layout for the sixth window using QGridLayout
    QGridLayout* sixthWindowLayout = new QGridLayout(this);
    sixthWindowLayout->setContentsMargins(2, 2, 2, 2); // Set smaller margins
    sixthWindowLayout->setVerticalSpacing(10);   // Set vertical spacing between rows

    // Background Image
    QLabel* backgroundImage = new QLabel(this);
    QPixmap pixmap(":assets/Icons/walls.jpg");  // Adjust the path to your image
    backgroundImage->setPixmap(pixmap);
    backgroundImage->setScaledContents(true);

    // Add the background image to the layout
    sixthWindowLayout->addWidget(backgroundImage, 0, 0, 4, 2); // Span across all rows and columns

    // Placeholder widget for centering
    QWidget* placeholderWidget = new QWidget(this);
    QGridLayout* placeholderLayout = new QGridLayout(placeholderWidget);
    placeholderWidget->setLayout(placeholderLayout);
    sixthWindowLayout->addWidget(placeholderWidget, 2, 0, 1, 2); // Add margin from the top
    sixthWindowLayout->setRowStretch(2, 1);  // Add stretch to push the buttons to the middle

    // Create components for the sixth window
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
    encryptAndSignButton = new QPushButton("Encrypt && Sign", this);
    encryptAndSignButton->setStyleSheet("QPushButton {"
                                "    background-color: rgb(0, 128, 0);" // Green color
                                "    border-radius: 10px;"
                                "    text-align: center;"
                                "    color: white;"
                                "    font-weight: bold;"
                                "}"
                                "QPushButton:hover {"
                                "    background-color: rgb(0, 100, 0);" // Darker green on hover
                                "}");

    // Set text color and font for the "encryptAndSignButton" button
    encryptAndSignButton->setPalette(palette);
    encryptAndSignButton->setFont(boldFont);
    encryptAndSignButton->setFixedWidth(300);

    // Create a horizontal layout for the "Finish" button
    QHBoxLayout* encryptAndSignLayout = new QHBoxLayout();
    encryptAndSignLayout->addWidget(encryptAndSignButton);

    // Add the "Finish" button to the layout
    sixthWindowLayout->addLayout(encryptAndSignLayout, 3, 0, 1, 2);

    // Add vertical spacer for padding
    QSpacerItem* verticalSpacer = new QSpacerItem(20, 80, QSizePolicy::Minimum, QSizePolicy::Expanding);
    sixthWindowLayout->addItem(verticalSpacer, 3, 0, 1, 2);

    // Set the layout for the sixth window
    setLayout(sixthWindowLayout);

    // Set the fixed size of the window
    setFixedSize(500, 400); // Adjust the size as needed

    connect(browseButton, &QPushButton::clicked, this, &SixthWindow::browseFile);
    connect(encryptAndSignButton, &QPushButton::clicked, this, &SixthWindow::encryptAndSignClicked);
}

SixthWindow::~SixthWindow()
{
}

void SixthWindow::browseFile()
{
    // Update the member variable with the selected file path
    selectedFilePath = QFileDialog::getOpenFileName(this, "Select File", QDir::homePath(), "Text files (*.txt)");
    filePathLineEdit->setText(selectedFilePath);
}

void SixthWindow::encryptAndSignClicked()
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

    // Call the encryptAndSign function
    encryptAndSign(selectedFilePath, aesKeyLineEdit->text());
}

void SixthWindow::encryptAndSign(const QString& inFile, const QString& key)
{
    // Call the encrypt function from SecondWindow
    SecondWindow secondWindow;
    secondWindow.encrypt(inFile, key);

    // Call the generateKey and sign functions from FourthWindow
    FourthWindow fourthWindow;
    fourthWindow.generateKey(inFile);
    fourthWindow.sign(inFile);
}


