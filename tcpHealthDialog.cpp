#include "tcpHealthDialog.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QPushButton>
#include <QFont>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QAbstractItemView>

#include "capture_file.h"

extern "C" {
#include <epan/tap.h>
#include <epan/to_str.h>
#include <file.h>
}

namespace {

struct ConnectionStats
{
    QString endpointA;
    QString endpointB;
    guint packets = 0;
    guint retransmissions = 0;
    guint duplicateAcks = 0;
    guint resets = 0;
};

struct TcpStats
{
    guint packets = 0;
    guint retransmissions = 0;
    guint duplicateAcks = 0;
    guint resets = 0;
    QMap<QString, ConnectionStats> connections;
};

enum EventType
{
    RetransmissionEvent,
    DuplicateAckEvent,
    ResetEvent
};

struct EventData
{
    TcpStats *stats;
    EventType type;
};

QString makeEndpoint(const address *addr, guint32 port)
{
    const gchar *text = address_to_str(wmem_packet_scope(), addr);
    QString result = text ? QString::fromUtf8(text) : "Unknown";

    if (port > 0) {
        result += QString(":%1").arg(port);
    }

    return result;
}

QString makeConnectionKey(const QString &first, const QString &second)
{
    if (first < second) {
        return first + " <-> " + second;
    }

    return second + " <-> " + first;
}

ConnectionStats &getConnection(TcpStats *stats, packet_info *pinfo)
{
    QString source = makeEndpoint(&pinfo->src, pinfo->srcport);
    QString destination = makeEndpoint(&pinfo->dst, pinfo->destport);
    QString key = makeConnectionKey(source, destination);

    if (!stats->connections.contains(key)) {
        ConnectionStats connection;

        if (source < destination) {
            connection.endpointA = source;
            connection.endpointB = destination;
        } else {
            connection.endpointA = destination;
            connection.endpointB = source;
        }

        stats->connections.insert(key, connection);
    }

    return stats->connections[key];
}

guint getProblemCount(const ConnectionStats &connection)
{
    return connection.retransmissions +
           connection.duplicateAcks +
           connection.resets;
}

double getProblemRate(guint packets, guint problems)
{
    if (packets == 0) {
        return 0.0;
    }

    return (static_cast<double>(problems) /
            static_cast<double>(packets)) * 100.0;
}

QString getHealth(guint packets, guint problems)
{
    if (packets == 0) {
        return "No Traffic";
    }

    double rate = getProblemRate(packets, problems);

    if (rate < 1.0) {
        return "Good";
    }

    if (rate < 5.0) {
        return "Warning";
    }

    return "Poor";
}

QTableWidgetItem *makeNumberItem(guint value)
{
    QTableWidgetItem *item = new QTableWidgetItem();
    item->setData(Qt::EditRole, static_cast<unsigned int>(value));
    item->setTextAlignment(Qt::AlignCenter);

    return item;
}

QTableWidgetItem *makeTextItem(const QString &text)
{
    QTableWidgetItem *item = new QTableWidgetItem(text);
    item->setTextAlignment(Qt::AlignCenter);

    return item;
}

tap_packet_status countTcpPacket(
    void *tapData,
    packet_info *pinfo,
    epan_dissect_t *,
    const void *)
{
    TcpStats *stats = static_cast<TcpStats *>(tapData);

    stats->packets++;

    ConnectionStats &connection = getConnection(stats, pinfo);
    connection.packets++;

    return TAP_PACKET_DONT_REDRAW;
}

tap_packet_status countTcpEvent(
    void *tapData,
    packet_info *pinfo,
    epan_dissect_t *,
    const void *)
{
    EventData *event = static_cast<EventData *>(tapData);
    ConnectionStats &connection = getConnection(event->stats, pinfo);

    if (event->type == RetransmissionEvent) {
        event->stats->retransmissions++;
        connection.retransmissions++;
    } else if (event->type == DuplicateAckEvent) {
        event->stats->duplicateAcks++;
        connection.duplicateAcks++;
    } else {
        event->stats->resets++;
        connection.resets++;
    }

    return TAP_PACKET_DONT_REDRAW;
}

}

TcpHealthDialog::TcpHealthDialog(QWidget *parent) :
    QDialog(parent)
{
    setWindowTitle("TCP Health Summary");
    resize(1000, 550);

    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    QLabel *titleLabel = new QLabel("TCP Health Summary");
    QFont titleFont = titleLabel->font();

    titleFont.setPointSize(16);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);

    mainLayout->addWidget(titleLabel);

    QHBoxLayout *summaryLayout = new QHBoxLayout();

    totalTcpLabel_ = new QLabel("TCP Packets: 0");
    retransmissionLabel_ = new QLabel("Retransmissions: 0");
    duplicateAckLabel_ = new QLabel("Duplicate ACKs: 0");
    resetLabel_ = new QLabel("Resets: 0");

    summaryLayout->addWidget(totalTcpLabel_);
    summaryLayout->addWidget(retransmissionLabel_);
    summaryLayout->addWidget(duplicateAckLabel_);
    summaryLayout->addWidget(resetLabel_);

    mainLayout->addLayout(summaryLayout);

    healthLabel_ = new QLabel("Connection Health: Unknown");

    QFont healthFont = healthLabel_->font();
    healthFont.setBold(true);
    healthLabel_->setFont(healthFont);

    mainLayout->addWidget(healthLabel_);

    connectionTable_ = new QTableWidget(this);
    connectionTable_->setColumnCount(8);

    QStringList headers;

    headers << "Endpoint A"
            << "Endpoint B"
            << "TCP Packets"
            << "Retransmissions"
            << "Duplicate ACKs"
            << "Resets"
            << "Problems"
            << "Health";

    connectionTable_->setHorizontalHeaderLabels(headers);

    connectionTable_->horizontalHeader()->setSectionResizeMode(
        QHeaderView::Stretch
    );

    connectionTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connectionTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    connectionTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    connectionTable_->setAlternatingRowColors(true);
    connectionTable_->setSortingEnabled(true);

    mainLayout->addWidget(connectionTable_);

    QHBoxLayout *buttonLayout = new QHBoxLayout();

    QPushButton *clearButton = new QPushButton("Clear");
    refreshButton_ = new QPushButton("Refresh");
    closeButton_ = new QPushButton("Close");

    buttonLayout->addStretch();
    buttonLayout->addWidget(clearButton);
    buttonLayout->addWidget(refreshButton_);
    buttonLayout->addWidget(closeButton_);

    mainLayout->addLayout(buttonLayout);

    connect(
        closeButton_,
        &QPushButton::clicked,
        this,
        &QDialog::close
    );

    connect(
        refreshButton_,
        &QPushButton::clicked,
        this,
        &TcpHealthDialog::refreshStatistics
    );

    connect(
        clearButton,
        &QPushButton::clicked,
        this,
        [this]()
        {
            totalTcpLabel_->setText("TCP Packets: 0");
            retransmissionLabel_->setText("Retransmissions: 0");
            duplicateAckLabel_->setText("Duplicate ACKs: 0");
            resetLabel_->setText("Resets: 0");
            healthLabel_->setText("Connection Health: Cleared");
            connectionTable_->setRowCount(0);
        }
    );
}

void TcpHealthDialog::refreshStatistics()
{
    capture_file *captureFile = CaptureFile::globalCapFile();

    if (captureFile == nullptr) {
        totalTcpLabel_->setText("TCP Packets: 0");
        retransmissionLabel_->setText("Retransmissions: 0");
        duplicateAckLabel_->setText("Duplicate ACKs: 0");
        resetLabel_->setText("Resets: 0");
        healthLabel_->setText("Connection Health: No capture loaded");
        connectionTable_->setRowCount(0);
        return;
    }

    TcpStats stats;

    EventData retransmissionData = {
        &stats,
        RetransmissionEvent
    };

    EventData duplicateAckData = {
        &stats,
        DuplicateAckEvent
    };

    EventData resetData = {
        &stats,
        ResetEvent
    };

    bool tcpRegistered = false;
    bool retransmissionRegistered = false;
    bool duplicateAckRegistered = false;
    bool resetRegistered = false;

    GString *error = nullptr;

    error = register_tap_listener(
        "tcp",
        &stats,
        nullptr,
        TL_REQUIRES_NOTHING,
        nullptr,
        countTcpPacket,
        nullptr,
        nullptr
    );

    if (error == nullptr) {
        tcpRegistered = true;
    } else {
        g_string_free(error, TRUE);
        healthLabel_->setText(
            "Connection Health: TCP listener failed"
        );
        connectionTable_->setRowCount(0);
        return;
    }

    error = register_tap_listener(
        "tcp",
        &retransmissionData,
        "tcp.analysis.retransmission",
        TL_REQUIRES_NOTHING,
        nullptr,
        countTcpEvent,
        nullptr,
        nullptr
    );

    if (error == nullptr) {
        retransmissionRegistered = true;
    } else {
        g_string_free(error, TRUE);
    }

    error = register_tap_listener(
        "tcp",
        &duplicateAckData,
        "tcp.analysis.duplicate_ack",
        TL_REQUIRES_NOTHING,
        nullptr,
        countTcpEvent,
        nullptr,
        nullptr
    );

    if (error == nullptr) {
        duplicateAckRegistered = true;
    } else {
        g_string_free(error, TRUE);
    }

    error = register_tap_listener(
        "tcp",
        &resetData,
        "tcp.flags.reset == 1",
        TL_REQUIRES_NOTHING,
        nullptr,
        countTcpEvent,
        nullptr,
        nullptr
    );

    if (error == nullptr) {
        resetRegistered = true;
    } else {
        g_string_free(error, TRUE);
    }

    cf_retap_packets(captureFile);

    if (tcpRegistered) {
        remove_tap_listener(&stats);
    }

    if (retransmissionRegistered) {
        remove_tap_listener(&retransmissionData);
    }

    if (duplicateAckRegistered) {
        remove_tap_listener(&duplicateAckData);
    }

    if (resetRegistered) {
        remove_tap_listener(&resetData);
    }

    totalTcpLabel_->setText(
        QString("TCP Packets: %1").arg(stats.packets)
    );

    retransmissionLabel_->setText(
        QString("Retransmissions: %1").arg(stats.retransmissions)
    );

    duplicateAckLabel_->setText(
        QString("Duplicate ACKs: %1").arg(stats.duplicateAcks)
    );

    resetLabel_->setText(
        QString("Resets: %1").arg(stats.resets)
    );

    guint totalProblems =
        stats.retransmissions +
        stats.duplicateAcks +
        stats.resets;

    guint affectedConnections = 0;

    for (
        QMap<QString, ConnectionStats>::const_iterator it =
            stats.connections.constBegin();
        it != stats.connections.constEnd();
        ++it
    ) {
        if (getProblemCount(it.value()) > 0) {
            affectedConnections++;
        }
    }

    double overallRate = getProblemRate(
        stats.packets,
        totalProblems
    );

    QString overallHealth = getHealth(
        stats.packets,
        totalProblems
    );

    healthLabel_->setText(
        QString(
            "Connection Health: %1 (%2% problem rate) | "
            "Connections: %3 | Affected: %4"
        )
        .arg(overallHealth)
        .arg(overallRate, 0, 'f', 2)
        .arg(stats.connections.size())
        .arg(affectedConnections)
    );

    connectionTable_->setSortingEnabled(false);
    connectionTable_->clearContents();
    connectionTable_->setRowCount(stats.connections.size());

    int row = 0;

    for (
        QMap<QString, ConnectionStats>::const_iterator it =
            stats.connections.constBegin();
        it != stats.connections.constEnd();
        ++it
    ) {
        const ConnectionStats &connection = it.value();

        guint problems = getProblemCount(connection);

        double problemRate = getProblemRate(
            connection.packets,
            problems
        );

        QString health = getHealth(
            connection.packets,
            problems
        );

        QTableWidgetItem *endpointAItem =
            new QTableWidgetItem(connection.endpointA);

        QTableWidgetItem *endpointBItem =
            new QTableWidgetItem(connection.endpointB);

        QTableWidgetItem *packetItem =
            makeNumberItem(connection.packets);

        QTableWidgetItem *retransmissionItem =
            makeNumberItem(connection.retransmissions);

        QTableWidgetItem *duplicateAckItem =
            makeNumberItem(connection.duplicateAcks);

        QTableWidgetItem *resetItem =
            makeNumberItem(connection.resets);

        QTableWidgetItem *problemItem =
            makeNumberItem(problems);

        QTableWidgetItem *healthItem =
            makeTextItem(health);

        QString tooltip =
            QString(
                "TCP packets: %1\n"
                "Retransmissions: %2\n"
                "Duplicate ACKs: %3\n"
                "Resets: %4\n"
                "Problem rate: %5%"
            )
            .arg(connection.packets)
            .arg(connection.retransmissions)
            .arg(connection.duplicateAcks)
            .arg(connection.resets)
            .arg(problemRate, 0, 'f', 2);

        endpointAItem->setToolTip(tooltip);
        endpointBItem->setToolTip(tooltip);
        packetItem->setToolTip(tooltip);
        retransmissionItem->setToolTip(tooltip);
        duplicateAckItem->setToolTip(tooltip);
        resetItem->setToolTip(tooltip);
        problemItem->setToolTip(tooltip);
        healthItem->setToolTip(tooltip);

        connectionTable_->setItem(row, 0, endpointAItem);
        connectionTable_->setItem(row, 1, endpointBItem);
        connectionTable_->setItem(row, 2, packetItem);
        connectionTable_->setItem(row, 3, retransmissionItem);
        connectionTable_->setItem(row, 4, duplicateAckItem);
        connectionTable_->setItem(row, 5, resetItem);
        connectionTable_->setItem(row, 6, problemItem);
        connectionTable_->setItem(row, 7, healthItem);

        row++;
    }

    connectionTable_->setSortingEnabled(true);
    connectionTable_->sortItems(6, Qt::DescendingOrder);
    connectionTable_->resizeRowsToContents();
}