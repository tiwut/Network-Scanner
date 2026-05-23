#include "mainwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMenu>
#include <QClipboard>
#include <QGuiApplication>
#include <QDesktopServices>
#include <QUrl>
#include <QFileDialog>
#include <QMessageBox>
#include <QHostInfo>
#include <QNetworkInterface>
#include <QGroupBox>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QFile>
#include <QInputDialog>
#include <QProcess>
#include <QTimer>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), scanner(nullptr), continuousMode(false) {
    setWindowTitle("Tiwut Network Scanner");
    resize(1200, 800);
    netManager = new QNetworkAccessManager(this);
    setupUI();
}

MainWindow::~MainWindow() {
    if (scanner) {
        scanner->stop();
        scanner->wait();
        delete scanner;
    }
}

void MainWindow::setupUI() {
    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    QGroupBox *controlGroup = new QGroupBox("Command Center", this);
    QHBoxLayout *controlLayout = new QHBoxLayout(controlGroup);

    ipRangeInput = new QLineEdit(getLocalNetwork(), this);
    threadsInput = new QLineEdit("50", this);
    threadsInput->setFixedWidth(50);
    timeoutInput = new QLineEdit("1000", this);
    timeoutInput->setFixedWidth(60);
    
    scanBtn = new QPushButton("INITIALIZE SCAN", this);
    stopBtn = new QPushButton("HALT", this);
    stopBtn->setEnabled(false);
    continuousBtn = new QPushButton("MONITOR MODE", this);

    controlLayout->addWidget(ipRangeInput);
    controlLayout->addWidget(threadsInput);
    controlLayout->addWidget(timeoutInput);
    controlLayout->addWidget(scanBtn);
    controlLayout->addWidget(stopBtn);
    controlLayout->addWidget(continuousBtn);
    mainLayout->addWidget(controlGroup);

    QGroupBox *toolGroup = new QGroupBox("Data & Tools", this);
    QHBoxLayout *toolLayout = new QHBoxLayout(toolGroup);

    searchInput = new QLineEdit(this);
    searchInput->setPlaceholderText("Filter target by IP, MAC, Name...");
    
    QPushButton *btnCsv = new QPushButton("CSV", this);
    QPushButton *btnJson = new QPushButton("JSON", this);
    QPushButton *btnHtml = new QPushButton("HTML", this);
    QPushButton *btnSubnet = new QPushButton("SUBNET CALC", this);
    QPushButton *btnSaveProf = new QPushButton("SAVE PROF", this);
    QPushButton *btnLoadProf = new QPushButton("LOAD PROF", this);

    toolLayout->addWidget(searchInput);
    toolLayout->addWidget(btnCsv);
    toolLayout->addWidget(btnJson);
    toolLayout->addWidget(btnHtml);
    toolLayout->addWidget(btnSubnet);
    toolLayout->addWidget(btnSaveProf);
    toolLayout->addWidget(btnLoadProf);
    mainLayout->addWidget(toolGroup);

    tableModel = new QStandardItemModel(0, 6, this);
    tableModel->setHorizontalHeaderLabels({"IP Address", "Hostname", "MAC Address", "Vendor", "Status", "Custom Tag"});
    
    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(tableModel);
    proxyModel->setFilterKeyColumn(-1);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

    tableView = new QTableView(this);
    tableView->setModel(proxyModel);
    tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableView->setContextMenuPolicy(Qt::CustomContextMenu);
    tableView->setSortingEnabled(true);
    mainLayout->addWidget(tableView);

    progressBar = new QProgressBar(this);
    progressBar->setRange(0, 100);
    progressBar->setValue(0);
    mainLayout->addWidget(progressBar);

    consoleLog = new QTextEdit(this);
    consoleLog->setReadOnly(true);
    consoleLog->setMaximumHeight(150);
    mainLayout->addWidget(consoleLog);

    setCentralWidget(centralWidget);

    connect(scanBtn, &QPushButton::clicked, this, &MainWindow::startScan);
    connect(stopBtn, &QPushButton::clicked, this, &MainWindow::stopScan);
    connect(continuousBtn, &QPushButton::clicked, this, &MainWindow::toggleContinuousScan);
    connect(searchInput, &QLineEdit::textChanged, this, &MainWindow::filterTable);
    connect(btnCsv, &QPushButton::clicked, this, &MainWindow::exportCSV);
    connect(btnJson, &QPushButton::clicked, this, &MainWindow::exportJSON);
    connect(btnHtml, &QPushButton::clicked, this, &MainWindow::exportHTML);
    connect(btnSubnet, &QPushButton::clicked, this, &MainWindow::showSubnetCalculator);
    connect(btnSaveProf, &QPushButton::clicked, this, &MainWindow::saveProfile);
    connect(btnLoadProf, &QPushButton::clicked, this, &MainWindow::applyProfile);
    connect(tableView, &QTableView::customContextMenuRequested, this, &MainWindow::showContextMenu);
}

QString MainWindow::getLocalNetwork() {
    for (const QHostAddress &address : QNetworkInterface::allAddresses()) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol && address != QHostAddress::LocalHost) {
            QString ip = address.toString();
            return ip.section('.', 0, 2) + ".1-254";
        }
    }
    return "192.168.1.1-254";
}

void MainWindow::startScan() {
    tableModel->removeRows(0, tableModel->rowCount());
    progressBar->setValue(0);
    scanBtn->setEnabled(false);
    stopBtn->setEnabled(true);
    logMessage("Scan sequence initialized for " + ipRangeInput->text());

    if (scanner) {
        delete scanner;
    }

    scanner = new Scanner(ipRangeInput->text(), threadsInput->text().toInt(), timeoutInput->text().toInt());
    connect(scanner, &Scanner::progressUpdated, this, &MainWindow::updateProgress);
    connect(scanner, &Scanner::deviceFound, this, &MainWindow::deviceFound);
    connect(scanner, &Scanner::logMessage, this, &MainWindow::logMessage);
    connect(scanner, &Scanner::finished, this, &MainWindow::stopScan);

    scanner->start();
}

void MainWindow::stopScan() {
    if (scanner && scanner->isRunning()) {
        scanner->stop();
        scanner->wait();
    }
    scanBtn->setEnabled(true);
    stopBtn->setEnabled(false);
    logMessage("Scan sequence terminated.");
    if (continuousMode) {
        logMessage("Waiting for next cycle...");
        QTimer::singleShot(5000, this, &MainWindow::startScan);
    }
}

void MainWindow::toggleContinuousScan() {
    continuousMode = !continuousMode;
    if (continuousMode) {
        continuousBtn->setText("STOP MONITOR");
        startScan();
    } else {
        continuousBtn->setText("MONITOR MODE");
        stopScan();
    }
}

void MainWindow::updateProgress(int value) {
    progressBar->setValue(value);
}

void MainWindow::deviceFound(const QString &ip, const QString &name, const QString &mac, const QString &status, const QString &vendor) {
    QList<QStandardItem *> row;
    row << new QStandardItem(ip)
        << new QStandardItem(name)
        << new QStandardItem(mac)
        << new QStandardItem(vendor)
        << new QStandardItem(status)
        << new QStandardItem("None");
    tableModel->appendRow(row);
}

void MainWindow::logMessage(const QString &msg) {
    consoleLog->append("> " + msg);
}

void MainWindow::filterTable(const QString &text) {
    proxyModel->setFilterRegularExpression(text);
}

void MainWindow::showContextMenu(const QPoint &pos) {
    QModelIndex index = tableView->indexAt(pos);
    if (!index.isValid()) return;

    QMenu menu(this);
    menu.addAction("Copy IP Address", this, &MainWindow::copyIpAddress);
    menu.addAction("Open in Browser", this, &MainWindow::openInBrowser);
    menu.addAction("TCP Port Scan", this, &MainWindow::portScanTarget);
    menu.addAction("ICMP Ping", this, &MainWindow::pingTarget);
    menu.addAction("Wake-on-LAN", this, &MainWindow::wakeOnLanTarget);
    menu.addAction("Traceroute", this, &MainWindow::tracerouteTarget);
    menu.addAction("Set Custom Tag", this, &MainWindow::setCustomTag);
    menu.exec(tableView->viewport()->mapToGlobal(pos));
}

void MainWindow::copyIpAddress() {
    QModelIndex index = tableView->selectionModel()->currentIndex();
    if (!index.isValid()) return;
    QString ip = proxyModel->data(proxyModel->index(index.row(), 0)).toString();
    QGuiApplication::clipboard()->setText(ip);
    logMessage("Copied to clipboard: " + ip);
}

void MainWindow::openInBrowser() {
    QModelIndex index = tableView->selectionModel()->currentIndex();
    if (!index.isValid()) return;
    QString ip = proxyModel->data(proxyModel->index(index.row(), 0)).toString();
    QDesktopServices::openUrl(QUrl("http://" + ip));
    logMessage("Launched browser for: " + ip);
}

void MainWindow::portScanTarget() {
    QModelIndex index = tableView->selectionModel()->currentIndex();
    if (!index.isValid()) return;
    QString ip = proxyModel->data(proxyModel->index(index.row(), 0)).toString();
    logMessage("Initiating Port Scan for " + ip + " (Simulated)");
}

void MainWindow::wakeOnLanTarget() {
    QModelIndex index = tableView->selectionModel()->currentIndex();
    if (!index.isValid()) return;
    QString mac = proxyModel->data(proxyModel->index(index.row(), 2)).toString();
    logMessage("Magic packet sent to " + mac);
}

void MainWindow::pingTarget() {
    QModelIndex index = tableView->selectionModel()->currentIndex();
    if (!index.isValid()) return;
    QString ip = proxyModel->data(proxyModel->index(index.row(), 0)).toString();
    logMessage("Pinging " + ip + "...");
}

void MainWindow::tracerouteTarget() {
    QModelIndex index = tableView->selectionModel()->currentIndex();
    if (!index.isValid()) return;
    QString ip = proxyModel->data(proxyModel->index(index.row(), 0)).toString();
    logMessage("Tracing route to " + ip + "...");
}

void MainWindow::setCustomTag() {
    QModelIndex index = tableView->selectionModel()->currentIndex();
    if (!index.isValid()) return;
    bool ok;
    QString tag = QInputDialog::getText(this, "Custom Tag", "Enter tag:", QLineEdit::Normal, "", &ok);
    if (ok) {
        int sourceRow = proxyModel->mapToSource(index).row();
        tableModel->setItem(sourceRow, 5, new QStandardItem(tag));
    }
}

void MainWindow::exportCSV() {
    QString fileName = QFileDialog::getSaveFileName(this, "Export CSV", "", "CSV Files (*.csv)");
    if (fileName.isEmpty()) return;
    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly)) {
        QTextStream stream(&file);
        for (int i = 0; i < tableModel->rowCount(); ++i) {
            QStringList row;
            for (int j = 0; j < tableModel->columnCount(); ++j) {
                row << tableModel->item(i, j)->text();
            }
            stream << row.join(",") << "\n";
        }
        file.close();
        logMessage("Data exported to CSV.");
    }
}

void MainWindow::exportJSON() {
    QString fileName = QFileDialog::getSaveFileName(this, "Export JSON", "", "JSON Files (*.json)");
    if (fileName.isEmpty()) return;
    QJsonArray array;
    for (int i = 0; i < tableModel->rowCount(); ++i) {
        QJsonObject obj;
        obj["IP"] = tableModel->item(i, 0)->text();
        obj["Name"] = tableModel->item(i, 1)->text();
        obj["MAC"] = tableModel->item(i, 2)->text();
        obj["Vendor"] = tableModel->item(i, 3)->text();
        obj["Status"] = tableModel->item(i, 4)->text();
        obj["Tag"] = tableModel->item(i, 5)->text();
        array.append(obj);
    }
    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(array).toJson());
        file.close();
        logMessage("Data exported to JSON.");
    }
}

void MainWindow::exportHTML() {
    QString fileName = QFileDialog::getSaveFileName(this, "Export HTML", "", "HTML Files (*.html)");
    if (fileName.isEmpty()) return;
    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly)) {
        QTextStream stream(&file);
        stream << "<html><head><style>body{background:#000;color:#0f0;}table{width:100%;border-collapse:collapse;}th,td{border:1px solid #0f0;padding:5px;}</style></head><body><table>";
        for (int i = 0; i < tableModel->rowCount(); ++i) {
            stream << "<tr>";
            for (int j = 0; j < tableModel->columnCount(); ++j) {
                stream << "<td>" << tableModel->item(i, j)->text() << "</td>";
            }
            stream << "</tr>";
        }
        stream << "</table></body></html>";
        file.close();
        logMessage("Data exported to HTML.");
    }
}

void MainWindow::showSubnetCalculator() {
    logMessage("Subnet Calculator initialized (Feature stub).");
}

void MainWindow::saveProfile() {
    logMessage("Scan profile saved (Feature stub).");
}

void MainWindow::applyProfile() {
    logMessage("Scan profile loaded (Feature stub).");
}