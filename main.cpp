#include <QApplication>
#include "mainwindow.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    QString hackerTheme = 
        "QWidget { background-color: #0D0D0D; color: #00FF00; font-family: 'Consolas', 'Courier New', monospace; font-size: 10pt; }"
        "QTableView { background-color: #050505; color: #00FF00; gridline-color: #004400; selection-background-color: #004400; selection-color: #00FF00; border: 1px solid #00FF00; }"
        "QHeaderView::section { background-color: #111111; color: #00FF00; border: 1px solid #004400; padding: 4px; }"
        "QPushButton { background-color: #1A1A1A; color: #00FF00; border: 1px solid #00FF00; padding: 5px 15px; }"
        "QPushButton:hover { background-color: #00FF00; color: #000000; }"
        "QPushButton:disabled { border: 1px solid #004400; color: #004400; }"
        "QLineEdit { background-color: #000000; color: #00FF00; border: 1px solid #00FF00; padding: 3px; }"
        "QProgressBar { border: 1px solid #00FF00; background-color: #000000; text-align: center; color: #FFFFFF; }"
        "QProgressBar::chunk { background-color: #00FF00; }"
        "QTextEdit { background-color: #000000; color: #00FF00; border: 1px solid #00FF00; }"
        "QMenu { background-color: #111111; color: #00FF00; border: 1px solid #00FF00; }"
        "QMenu::item:selected { background-color: #00FF00; color: #000000; }"
        "QGroupBox { border: 1px solid #00FF00; margin-top: 10px; }"
        "QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 3px; }";

    app.setStyleSheet(hackerTheme);

    MainWindow w;
    w.show();

    return app.exec();
}