// mainwindow.cpp

#include "mainwindow.h"
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    // Set up the main window
    setWindowTitle("Security_Project");

    // Set the application icon (logo)
    QIcon appIcon(":assets/Icons/logo.jpg"); // Adjust the path accordingly
    setWindowIcon(appIcon);

    // Create a central widget
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    // Create a grid layout for the central widget
    QGridLayout *mainLayout = new QGridLayout(centralWidget);
    mainLayout->setContentsMargins(2, 2, 2, 2); // Set smaller margins
    mainLayout->setVerticalSpacing(10);   // Increase the vertical spacing

    // Background Image
    QLabel* backgroundImage = new QLabel(this);
    QPixmap pixmap(":assets/Icons/walls.jpg");  // Adjust the path to your image
    backgroundImage->setPixmap(pixmap);
    backgroundImage->setScaledContents(true);

    // Add the background image to the layout
    mainLayout->addWidget(backgroundImage, 0, 0, 4, 2); // Span across all rows and columns

    // Placeholder widget for centering
    QWidget* placeholderWidget = new QWidget(this);
    QGridLayout* placeholderLayout = new QGridLayout(placeholderWidget);
    placeholderWidget->setLayout(placeholderLayout);
    mainLayout->addWidget(placeholderWidget, 2, 0, 1, 2); // Add margin from the top
    mainLayout->setRowStretch(2, 1);  // Add stretch to push the buttons to the middle

    // Add "Choose Operation" label
    QLabel *chooseOperationLabel = new QLabel("Choose Operation", this);
    QFont labelFont;
    labelFont.setBold(true);
    labelFont.setPointSize(24); // Adjust the font size as needed
    chooseOperationLabel->setFont(labelFont);
    chooseOperationLabel->setStyleSheet("color: white;");
    chooseOperationLabel->setAlignment(Qt::AlignHCenter | Qt::AlignBottom); // Align to the bottom
    chooseOperationLabel->setMargin(20); // Add margin to position lower

    // Add the label to the layout
    mainLayout->addWidget(chooseOperationLabel, 0, 0, 1, 2); // Span across all columns

    // Buttons
    QStringList buttonNames = {"EncryptAES", "DecryptAES", "&Sign", "&Verify", "Encrypt && Sign", "Decrypt && Verify"};
    QStringList buttonSlots = {"encryptAESClicked", "decryptAESClicked", "signClicked", "verifyClicked", "encryptAndSignClicked", "decryptAndVerifyClicked"};

    for (int i = 0; i < buttonNames.size(); ++i) {
        QPushButton *button = new QPushButton(buttonNames.at(i), this);
        button->setStyleSheet("background-color: rgb(139, 0, 0);");
        button->setStyleSheet("QPushButton {"
                              "    background-color: rgb(139, 0, 0);"
                              "    border-radius: 10px;"
                              "    text-align: center;"
                              "    color: white;"
                              "    font-weight: bold;"
                              "}"
                              "QPushButton:hover {"
                              "    background-color: rgb(100, 0, 0);"
                              "}");
        placeholderLayout->setSpacing(10);  // Adjust the spacing as needed

        if (i == 0) connect(button, &QPushButton::clicked, this, &MainWindow::encryptAESClicked);
        else if (i == 1) connect(button, &QPushButton::clicked, this, &MainWindow::decryptAESClicked);
        else if (i == 2) connect(button, &QPushButton::clicked, this, &MainWindow::signClicked);
        else if (i == 3) connect(button, &QPushButton::clicked, this, &MainWindow::verifyClicked);
        else if (i == 4) connect(button, &QPushButton::clicked, this, &MainWindow::encryptAndSignClicked);
        else if (i == 5) connect(button, &QPushButton::clicked, this, &MainWindow::decryptAndVerifyClicked);
        placeholderLayout->addWidget(button, i / 2, i % 2);
    }

    // Set the layout
    centralWidget->setLayout(mainLayout);

    // Initialize font sizes and styles
    adjustButtonSize();

    // Set the fixed size of the window
    setFixedSize(800, 600); // Adjust the size as needed
}





MainWindow::~MainWindow() {
    // Use the QLayout destructor directly
    delete centralWidget()->layout();
}

void MainWindow::resizeEvent(QResizeEvent *event) {
    QMainWindow::resizeEvent(event);
    emit resized();
    adjustButtonSize();  // Call the function to adjust button size
}

void MainWindow::encryptAESClicked() {
    // Add your logic for EncryptAES button click
    secondWindow = new SecondWindow();
    secondWindow->show();
}

void MainWindow::decryptAESClicked() {
    // Add your logic for DecryptAES button click
    thirdWindow = new ThirdWindow();
    thirdWindow->show();
}

void MainWindow::signClicked() {
    // Add your logic for Sign button click
    fourthWindow = new FourthWindow();
    fourthWindow->show();
}

void MainWindow::verifyClicked() {
    // Add your logic for Verify button click
    fifthWindow = new FifthWindow();
    fifthWindow->show();
}

void MainWindow::encryptAndSignClicked() {
    // Add your logic for Encrypt & Sign button click
    sixthWindow = new SixthWindow();
    sixthWindow->show();
}

void MainWindow::decryptAndVerifyClicked() {
    // Add your logic for Decrypt & Verify button click
    seventhWindow = new SeventhWindow();
    seventhWindow->show();
}

void MainWindow::adjustButtonSize() {
    // Calculate the font size based on both height and width
    int fontSize = qMin(height() / 20, width() / 40);

    QList<QPushButton *> buttons = findChildren<QPushButton *>();
    for (QPushButton *button : buttons) {
        QFont font = button->font();
        font.setPointSize(fontSize);
        button->setFont(font);
    }
}
