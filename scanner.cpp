#include "scanner.h"
#include <QProcess>
#include <QHostInfo>
#include <QEventLoop>
#include <QTimer>
#include <QRegularExpression>
#include <QNetworkInterface>

Scanner::Scanner(const QString &range, int threads, int timeout, QObject *parent)
    : QThread(parent), ipRange(range), maxThreads(threads), pingTimeout(timeout), m_stop(false) {
}

void Scanner::stop() {
    m_stop = true;
}

void Scanner::run() {
    QStringList ips = parseRange(ipRange);
    int total = ips.size();
    if (total == 0) {
        emit logMessage("Invalid IP range format.");
        return;
    }

    for (int i = 0; i < total; ++i) {
        if (m_stop) break;

        QString ip = ips[i];
        QProcess pingProc;
        QStringList args;
#ifdef Q_OS_WIN
        args << "-n" << "1" << "-w" << QString::number(pingTimeout) << ip;
#else
        args << "-c" << "1" << "-W" << QString::number(pingTimeout / 1000.0) << ip;
#endif
        pingProc.start("ping", args);
        pingProc.waitForFinished();

        if (pingProc.exitCode() == 0) {
            QString name = resolveHostname(ip);
            QString mac = getMacFromArp(ip);
            QString vendor = lookupVendor(mac);
            emit deviceFound(ip, name, mac, "Online", vendor);
            emit logMessage("Target acquired: " + ip);
        }

        emit progressUpdated((i + 1) * 100 / total);
    }
}

QStringList Scanner::parseRange(const QString &range) {
    QStringList result;
    if (range.contains("-")) {
        QString base = range.section('.', 0, 2);
        QString lastPart = range.section('.', 3, 3);
        int start = lastPart.section('-', 0, 0).toInt();
        int end = lastPart.section('-', 1, 1).toInt();
        for (int i = start; i <= end; ++i) {
            result.append(base + "." + QString::number(i));
        }
    } else {
        result.append(range);
    }
    return result;
}

QString Scanner::resolveHostname(const QString &ip) {
    QHostInfo info = QHostInfo::fromName(ip);
    if (info.error() == QHostInfo::NoError && !info.hostName().isEmpty()) {
        return info.hostName();
    }
    return "Unknown";
}

QString Scanner::getMacFromArp(const QString &ip) {
    QProcess arpProc;
    arpProc.start("arp", QStringList() << "-a");
    arpProc.waitForFinished();
    QString output = arpProc.readAllStandardOutput();

    QString safeIp = ip;
    QRegularExpression re(safeIp.replace(".", "\\.") + "\\s+([0-9a-fA-F:-]+)");
    QRegularExpressionMatch match = re.match(output);
    if (match.hasMatch()) {
        return match.captured(1).toUpper();
    }
    return "N/A";
}

QString Scanner::lookupVendor(const QString &mac) {
    if (mac == "N/A") return "Unknown";
    QString prefix = mac.left(8).replace("-", ":");
    if (prefix == "00:50:56" || prefix == "00:0C:29") return "VMware";
    if (prefix == "08:00:27") return "VirtualBox";
    if (prefix == "B8:27:EB" || prefix == "DC:A6:32") return "Raspberry Pi";
    return "Generic/Unknown";
}