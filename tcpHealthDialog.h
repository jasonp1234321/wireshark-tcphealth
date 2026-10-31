#ifndef TCP_HEALTH_DIALOG_H
#define TCP_HEALTH_DIALOG_H

#include <QDialog>

class QLabel;
class QTableWidget;
class QPushButton;

class TcpHealthDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TcpHealthDialog(QWidget *parent = nullptr);

private slots:
    void refreshStatistics();

private:
    QLabel *totalTcpLabel_;
    QLabel *retransmissionLabel_;
    QLabel *duplicateAckLabel_;
    QLabel *resetLabel_;
    QLabel *healthLabel_;

    QTableWidget *connectionTable_;

    QPushButton *refreshButton_;
    QPushButton *closeButton_;
};

#endif