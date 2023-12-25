#include "SeventhWindow.h"
#include "thirdwindow.h"
#include "fifthwindow.h"
#include <QMessageBox>

SeventhWindow::SeventhWindow(QWidget *parent)
    : QWidget(parent)
{
    setWindowTitle("Decrypt & Verify Configuration");

    // Set the application icon (logo)
    QIcon appIcon(":/logo.png"); // Adjust the path accordingly
    setWindowIcon(appIcon);

    // Set up layout for the seventh window using QGridLayout
    QGridLayout *seventhWindowLayout = new QGridLayout(this);
    seventhWindowLayout->setContentsMargins(2, 2, 2, 2); // Set smaller margins
    seventhWindowLayout->setVerticalSpacing(10);          // Set vertical spacing between rows

    // Background Image
    QLabel *backgroundImage = new QLabel(this);
    QPixmap pixmap(":/walls.jpg"); // Adjust the path to your image
    backgroundImage->setPixmap(pixmap);
    backgroundImage->setScaledContents(true);

    // Add the background image to the layout
    seventhWindowLayout->addWidget(backgroundImage, 0, 0, 5, 2); // Span across all rows and columns

    // Placeholder widget for centering
    QWidget *placeholderWidget = new QWidget(this);
    QGridLayout *placeholderLayout = new QGridLayout(placeholderWidget);
    placeholderWidget->setLayout(placeholderLayout);
    seventhWindowLayout->addWidget(placeholderWidget, 2, 0, 1, 2); // Add margin from the top
    seventhWindowLayout->setRowStretch(2, 1);                      // Add stretch to push the buttons to the middle

    // Create components for the seventh window
    aesKeyLabel = new QLabel("AES256 Dec. Key", this);
    aesKeyLineEdit = new QLineEdit(this);
    aesKeyLineEdit->setFixedWidth(300);

    filePathLabel = new QLabel("Cipher text file path", this);
    filePathLineEdit = new QLineEdit(this);
    filePathLineEdit->setMaximumWidth(200);

    sigFilePathLabel = new QLabel("Signature file path", this);
    sigFilePathLineEdit = new QLineEdit(this);
    sigFilePathLineEdit->setMaximumWidth(200);

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

    browseSigButton = new QPushButton("Browse Signature", this);
    browseSigButton->setStyleSheet("QPushButton {"
                                   "    background-color: rgb(139, 0, 0);"
                                   "    border-radius: 10px;"
                                   "    text-align: center;"
                                   "    color: white;"
                                   "    font-weight: bold;"
                                   "}"
                                   "QPushButton:hover {"
                                   "    background-color: rgb(100, 0, 0);"
                                   "}");

    encryptAndSignButton = new QPushButton("Decrypt && Verify", this);
    encryptAndSignButton->setStyleSheet("QPushButton {"
                                        "    background-color: rgb(0, 128, 0);"
                                        "    border-radius: 10px;"
                                        "    text-align: center;"
                                        "    color: white;"
                                        "    font-weight: bold;"
                                        "}"
                                        "QPushButton:hover {"
                                        "    background-color: rgb(0, 100, 0);"
                                        "}");

    // Set text color and font for labels
    QPalette palette;
    palette.setColor(QPalette::WindowText, Qt::white);
    aesKeyLabel->setPalette(palette);
    filePathLabel->setPalette(palette);
    sigFilePathLabel->setPalette(palette);

    QFont boldFont;
    boldFont.setBold(true);
    boldFont.setPointSize(12); // Increased font size
    aesKeyLabel->setFont(boldFont);
    filePathLabel->setFont(boldFont);
    sigFilePathLabel->setFont(boldFont);

    // Set text color and font for the button
    palette.setColor(QPalette::ButtonText, Qt::white);
    browseButton->setPalette(palette);
    browseButton->setFont(boldFont);
    browseSigButton->setPalette(palette);
    browseSigButton->setFont(boldFont);
    encryptAndSignButton->setPalette(palette);
    encryptAndSignButton->setFont(boldFont);

    // Add components to the layout
    placeholderLayout->addWidget(aesKeyLabel, 0, 0);
    placeholderLayout->addWidget(aesKeyLineEdit, 0, 1);

    placeholderLayout->addWidget(filePathLabel, 1, 0);
    placeholderLayout->addWidget(filePathLineEdit, 1, 1);
    placeholderLayout->addWidget(browseButton, 1, 2, 1, 2); // Browse button takes remaining width

    placeholderLayout->addWidget(sigFilePathLabel, 2, 0);
    placeholderLayout->addWidget(sigFilePathLineEdit, 2, 1);
    placeholderLayout->addWidget(browseSigButton, 2, 2, 1, 2); // Browse button takes remaining width

    placeholderLayout->addWidget(encryptAndSignButton, 3, 1, 1, 1, Qt::AlignRight); // Align to the right

    browseButton->setFixedWidth(150);
    browseSigButton->setFixedWidth(150);
    encryptAndSignButton->setFixedWidth(200);

    // Create a vertical spacer for padding
    QSpacerItem *verticalSpacer = new QSpacerItem(20, 80, QSizePolicy::Minimum, QSizePolicy::Expanding);
    seventhWindowLayout->addItem(verticalSpacer, 4, 0, 1, 2); // Placed in the row below

    // Set the layout for the seventh window
    setLayout(seventhWindowLayout);

    // Set the fixed size of the window
    setFixedSize(500, 500); // Adjust the size as needed

    connect(browseButton, &QPushButton::clicked, this, &SeventhWindow::browseFile);
    connect(browseSigButton, &QPushButton::clicked, this, &SeventhWindow::browseSigFile);
    connect(encryptAndSignButton, &QPushButton::clicked, this, &SeventhWindow::decryptAndVerifyClicked);
}



void SeventhWindow::browseFile()
{
    QString filePath = QFileDialog::getOpenFileName(this, "Select Cipher Text File", "", "Encrypted Files (*.enc)");
    if (!filePath.isEmpty())
    {
        filePathLineEdit->setText(filePath);
    }
}

void SeventhWindow::browseSigFile()
{
    QString sigFilePath = QFileDialog::getOpenFileName(this, "Select Signature File", "", "Siganature Files (*.sig)");
    if (!sigFilePath.isEmpty())
    {
        sigFilePathLineEdit->setText(sigFilePath);
    }
}

void SeventhWindow::decryptAndVerifyClicked()
{
    QString key = aesKeyLineEdit->text();
    QString cipherTextFilePath = filePathLineEdit->text();
    QString sigFilePath = sigFilePathLineEdit->text();

    if (key.isEmpty() || cipherTextFilePath.isEmpty() || sigFilePath.isEmpty())
    {
        QMessageBox::warning(this, "Incomplete Information", "Please enter the AES key, select the cipher text file, and select the signature file.");
        return;
    }

    // Call the decryptAndVerify function with the provided key and file paths
    decryptAndVerify(cipherTextFilePath, key, sigFilePath);
}

void SeventhWindow::decryptAndVerify(const QString &inFile, const QString &key, const QString &sigFile)
{
    // Call the decrypt function from ThirdWindow
    ThirdWindow thirdWindow;
    thirdWindow.decrypt(inFile, key);

    QFileInfo fileInfo(inFile);
    QString decryptedFilePath = fileInfo.path() + "decrypted_file.txt";

    // Call the verify function from FifthWindow
    FifthWindow fifthWindow;
    fifthWindow.verify(decryptedFilePath,sigFile);
}

SeventhWindow::~SeventhWindow()
{
    // Destructor implementation, if needed
}
