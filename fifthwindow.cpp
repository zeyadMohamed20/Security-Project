// fifthwindow.cpp
#include "fifthwindow.h"
#include <QDebug>
#include <QFileInfo>
#include <QMessageBox>
#include <QProcess>

FifthWindow::FifthWindow(QWidget *parent)
    : QWidget(parent)
{
    setWindowTitle("Verify Configuration");

    // Set the application icon (logo)
    QIcon appIcon(":/logo.png"); // Adjust the path accordingly
    setWindowIcon(appIcon);

    // Set up layout for the fifth window using QGridLayout
    QGridLayout* fifthWindowLayout = new QGridLayout(this);
    fifthWindowLayout->setContentsMargins(2, 2, 2, 2); // Set smaller margins
    fifthWindowLayout->setVerticalSpacing(10);   // Set vertical spacing between rows

    // Background Image
    QLabel* backgroundImage = new QLabel(this);
    QPixmap pixmap(":/walls.jpg");  // Adjust the path to your image
    backgroundImage->setPixmap(pixmap);
    backgroundImage->setScaledContents(true);

    // Add the background image to the layout
    fifthWindowLayout->addWidget(backgroundImage, 0, 0, 4, 2); // Span across all rows and columns

    // Placeholder widget for centering
    QWidget* placeholderWidget = new QWidget(this);
    QGridLayout* placeholderLayout = new QGridLayout(placeholderWidget);
    placeholderWidget->setLayout(placeholderLayout);
    fifthWindowLayout->addWidget(placeholderWidget, 2, 0, 1, 2); // Add margin from the top
    fifthWindowLayout->setRowStretch(2, 1);  // Add stretch to push the buttons to the middle

    // Create components for the fifth window
    plainFilePathLabel = new QLabel("Plain text file path", this);
    plainFilePathLineEdit = new QLineEdit(this);

    // Set maximum width for the file path QLineEdit
    plainFilePathLineEdit->setMaximumWidth(200);  // Adjust the width as needed

    sigFilePathLabel = new QLabel("Signature file path", this);
    sigFilePathLineEdit = new QLineEdit(this);

    // Set maximum width for the file path QLineEdit
    sigFilePathLineEdit->setMaximumWidth(200);  // Adjust the width as needed

    browsePlainTextButton = new QPushButton("Browse Plain Text", this);
    browsePlainTextButton->setStyleSheet("QPushButton {"
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

    // Set text color and font for labels
    QPalette palette;
    palette.setColor(QPalette::WindowText, Qt::white);
    plainFilePathLabel->setPalette(palette);
    sigFilePathLabel->setPalette(palette);

    QFont boldFont;
    boldFont.setBold(true);
    boldFont.setPointSize(12);  // Increased font size
    plainFilePathLabel->setFont(boldFont);
    sigFilePathLabel->setFont(boldFont);

    // Set text color and font for the buttons
    palette.setColor(QPalette::ButtonText, Qt::white);
    browsePlainTextButton->setPalette(palette);
    browsePlainTextButton->setFont(boldFont);

    browseSigButton->setPalette(palette);
    browseSigButton->setFont(boldFont);

    // Add components to the layout
    placeholderLayout->addWidget(plainFilePathLabel, 0, 0);
    placeholderLayout->addWidget(plainFilePathLineEdit, 0, 1);
    placeholderLayout->addWidget(browsePlainTextButton, 0, 2, 1, 2); // Browse button takes remaining width

    placeholderLayout->addWidget(sigFilePathLabel, 1, 0);
    placeholderLayout->addWidget(sigFilePathLineEdit, 1, 1);
    placeholderLayout->addWidget(browseSigButton, 1, 2, 1, 2); // Browse button takes remaining width

    browsePlainTextButton->setFixedWidth(150);
    browseSigButton->setFixedWidth(150);

    // Create "Verify" button
    verifyButton = new QPushButton("Verify", this);
    verifyButton->setStyleSheet("QPushButton {"
                                "    background-color: rgb(0, 128, 0);" // Green color
                                "    border-radius: 10px;"
                                "    text-align: center;"
                                "    color: white;"
                                "    font-weight: bold;"
                                "}"
                                "QPushButton:hover {"
                                "    background-color: rgb(0, 100, 0);" // Darker green on hover
                                "}");

    // Set text color and font for the "Verify" button
    verifyButton->setPalette(palette);
    verifyButton->setFont(boldFont);
    verifyButton->setFixedWidth(300);

    // Create a horizontal layout for the "Verify" button
    QHBoxLayout* verifyLayout = new QHBoxLayout();
    verifyLayout->addWidget(verifyButton);

    // Add the "Verify" button to the layout
    fifthWindowLayout->addLayout(verifyLayout, 3, 0, 1, 2); // Placed in the row below

    // Add vertical spacer for padding
    QSpacerItem* verticalSpacer = new QSpacerItem(20, 80, QSizePolicy::Minimum, QSizePolicy::Expanding);
    fifthWindowLayout->addItem(verticalSpacer, 3, 0, 1, 2); // Placed in the row below

    // Set the layout for the fifth window
    setLayout(fifthWindowLayout);

    // Set the fixed size of the window
    setFixedSize(500, 400); // Adjust the size as needed

    connect(browsePlainTextButton, &QPushButton::clicked, this, &FifthWindow::browsePlainTextFile);
    connect(browseSigButton, &QPushButton::clicked, this, &FifthWindow::browseSigFile);
    connect(verifyButton, &QPushButton::clicked, this, &FifthWindow::verifyClicked);
}

FifthWindow::~FifthWindow()
{
}

void FifthWindow::browsePlainTextFile()
{
    // Update the member variable with the selected file path
    selectedPlainTextFilePath = QFileDialog::getOpenFileName(this, "Select Plain Text File", QDir::homePath(), "Text files (*.txt)");
    plainFilePathLineEdit->setText(selectedPlainTextFilePath);
}

void FifthWindow::browseSigFile()
{
    // Update the member variable with the selected file path
    selectedSigFilePath = QFileDialog::getOpenFileName(this, "Select Signature File", QDir::homePath(), "Signature files (*.sig)");
    sigFilePathLineEdit->setText(selectedSigFilePath);
}

void FifthWindow::verifyClicked()
{
    // Check if both file paths are entered
    if (selectedPlainTextFilePath.isEmpty() || selectedSigFilePath.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please select both plain text and signature files.");
        return;
    }

    // Perform the verification action using selectedPlainTextFilePath and selectedSigFilePath
    // For now, let's print a message
    qDebug() << "Plain Text File Path: " << selectedPlainTextFilePath;
    qDebug() << "Signature File Path: " << selectedSigFilePath;

    // Call the verify function
    verify(selectedPlainTextFilePath, selectedSigFilePath);
}

void FifthWindow::verify(const QString& plainTextFile, const QString& sigFile)
{
    QFileInfo fileInfo(plainTextFile);

    // Adjust the paths for the public key and signature files
    QString publicKeyPath = fileInfo.path() + "public.pem";

    // Construct the command
    QString command = "openssl pkeyutl -verify -in \"" + plainTextFile + "\" -sigfile \"" + sigFile + "\" -pubin -inkey \"" + publicKeyPath + "\"";

    // Run the command using QProcess
    QProcess process;
    process.start(command);
    process.waitForFinished();

    if (process.exitCode() == 0) {
        // Verification succeeded
        QString message = "Verification is successful.";
        QMessageBox::information(this, "Verification Success", message);
    } else {
        // Verification failed
        QString errorMessage = "Verification failed. Please check your input and try again.";
        QMessageBox::critical(this, "Verification Error", errorMessage);
    }
}
