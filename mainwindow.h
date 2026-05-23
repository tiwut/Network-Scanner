#pragma once

#include <QMainWindow>
#include <QTableView>
#include <QStandardItemModel>
#include <QLineEdit>
#include <QPushButton>
#include <QProgressBar>
#include <QTextEdit>
#include <QSortFilterProxyModel>
#include <QNetworkAccessManager>
#include "scanner.h"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void startScan();
    void stopScan();
    void updateProgress(int value);
    void deviceFound(const QString &ip, const QString &name, const QString &mac, const QString &status, const QString &vendor);
    void logMessage(const QString &msg);
    void exportCSV();
    void exportJSON();
    void exportHTML();
    void showContextMenu(const QPoint &pos);
    void filterTable(const QString &text);
    void portScanTarget();
    void wakeOnLanTarget();
    void copyIpAddress();
    void openInBrowser();
    void pingTarget();
    void tracerouteTarget();
    void setCustomTag();
    void toggleContinuousScan();
    void showSubnetCalculator();
    void applyProfile();
    void saveProfile();

private:
    void setupUI();
    QString getLocalNetwork();

    QTableView *tableView;
    QStandardItemModel *tableModel;
    QSortFilterProxyModel *proxyModel;
    QLineEdit *ipRangeInput;
    QLineEdit *searchInput;
    QLineEdit *threadsInput;
    QLineEdit *timeoutInput;
    QPushButton *scanBtn;
    QPushButton *stopBtn;
    QPushButton *continuousBtn;
    QProgressBar *progressBar;
    QTextEdit *consoleLog;
    Scanner *scanner;
    QNetworkAccessManager *netManager;
    bool continuousMode;
};