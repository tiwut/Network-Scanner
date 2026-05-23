#pragma once

#include <QThread>
#include <QString>
#include <QStringList>

class Scanner : public QThread {
    Q_OBJECT

public:
    Scanner(const QString &range, int threads, int timeout, QObject *parent = nullptr);
    void stop();

signals:
    void progressUpdated(int value);
    void deviceFound(const QString &ip, const QString &name, const QString &mac, const QString &status, const QString &vendor);
    void logMessage(const QString &msg);

protected:
    void run() override;

private:
    QString ipRange;
    int maxThreads;
    int pingTimeout;
    bool m_stop;

    QStringList parseRange(const QString &range);
    QString resolveHostname(const QString &ip);
    QString getMacFromArp(const QString &ip);
    QString lookupVendor(const QString &mac);
};