package com.radhika.dpi.capture;

import java.util.List;
import java.util.Scanner;

import com.radhika.dpi.security.PortScanDetector;
import com.radhika.dpi.statistics.HostStatisticsManager;
import com.radhika.dpi.statistics.Statistics;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

import com.radhika.dpi.report.PDFReportGenerator;
import com.radhika.dpi.report.ReportGenerator;
import com.radhika.dpi.parser.TCPFlagParser;
import com.radhika.dpi.flow.FlowManager;
import com.radhika.dpi.model.PacketInfo;
import com.radhika.dpi.parser.DNSParser;
import com.radhika.dpi.parser.EthernetParser;
import com.radhika.dpi.parser.IPv4Parser;
import com.radhika.dpi.parser.TCPParser;
import com.radhika.dpi.parser.UDPParser;
import com.radhika.dpi.parser.HTTPParser;

public class PacketCapture {

    public static void main(String[] args)
            throws PcapNativeException, NotOpenException {

        // Get all network interfaces
        List<PcapNetworkInterface> devices = Pcaps.findAllDevs();

        if (devices.isEmpty()) {
            System.out.println("No network interfaces found!");
            return;
        }

        // Display interfaces
        System.out.println("Available Network Interfaces:\n");

        for (int i = 0; i < devices.size(); i++) {
            System.out.println((i + 1) + ". " + devices.get(i).getDescription());
        }

        // User selects interface
        Scanner scanner = new Scanner(System.in);

        System.out.print("\nEnter Interface Number: ");
        int choice = scanner.nextInt();

        if (choice < 1 || choice > devices.size()) {
            System.out.println("Invalid Choice!");
            scanner.close();
            return;
        }

        PcapNetworkInterface selectedDevice = devices.get(choice - 1);

        System.out.println("\nSelected Interface:");
        System.out.println(selectedDevice.getDescription());

        // Open interface
        PcapHandle handle = selectedDevice.openLive(
                65536,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                10);

        System.out.println("\nListening for packets...\n");

        while (true) {

            Packet packet = handle.getNextPacket();

            if (packet == null) {
                continue;
            }

            byte[] raw = packet.getRawData();

            PacketInfo info = new PacketInfo();
            Statistics.totalPackets++;

            // Parse Ethernet Header
            EthernetParser.parse(raw, info);
            if ("IPv4".equals(info.ethernetType)) {
                Statistics.ipv4Packets++;
            } else if ("IPv6".equals(info.ethernetType)) {
                Statistics.ipv6Packets++;
            } else if ("ARP".equals(info.ethernetType)) {
                Statistics.arpPackets++;
            }

            System.out.println("========================");
            System.out.println("Packet Length : " + raw.length);
            System.out.println("Ethernet Type : " + info.ethernetType);

            // Parse only IPv4 packets
            if ("IPv4".equals(info.ethernetType)) {

                // Parse IPv4 Header
                IPv4Parser.parse(raw, info);
                if ("TCP".equals(info.protocol)) {
                    Statistics.tcpPackets++;
                } else if ("UDP".equals(info.protocol)) {
                    Statistics.udpPackets++;
                }

                // Parse TCP Header
                TCPParser.parse(raw, info);

                // Parse TCP Flags
                TCPFlagParser.parse(raw, info);

                PortScanDetector.detect(info);

                // Parse UDP Header
                UDPParser.parse(raw, info);
                if ("HTTP".equals(info.service)) {
                    Statistics.httpPackets++;
                } else if ("HTTPS".equals(info.service)) {
                    Statistics.httpsPackets++;
                } else if ("DNS".equals(info.service)) {
                    Statistics.dnsPackets++;
                } else if ("SSH".equals(info.service)) {
                    Statistics.sshPackets++;
                }

                // Parse HTTP Payload
                if ("HTTP".equals(info.service)) {
                    HTTPParser.parse(raw, info);
                }

                if (info.httpMethod != null) {
                    System.out.println("\n========== HTTP REQUEST ==========");
                    System.out.println("Method      : " + info.httpMethod);
                    System.out.println("Path        : " + info.httpPath);
                    System.out.println("Version     : " + info.httpVersion);
                    System.out.println("Host        : " + info.httpHost);
                    System.out.println("User-Agent  : " + info.httpUserAgent);
                }

                if (info.httpStatusCode != 0) {
                    System.out.println("\n========== HTTP RESPONSE ==========");
                    System.out.println("Version      : " + info.httpVersion);
                    System.out.println("Status Code  : " + info.httpStatusCode);
                    System.out.println("Status       : " + info.httpStatus);
                    System.out.println("Server       : " + info.httpServer);
                    System.out.println("Content-Type : " + info.httpContentType);
                }

                // Check if this is a DNS packet
                if (DNSParser.isDNS(info)) {
                    System.out.println("DNS Packet Detected!");
                }

                // Update flow statistics
                if ("TCP".equals(info.protocol) || "UDP".equals(info.protocol)) {
                    FlowManager.updateFlow(info, raw.length);
                }

                // Update Host Statistics (Top Talkers)
                HostStatisticsManager.updateHost(info.sourceIP, raw.length);

                System.out.println("Source IP      : " + info.sourceIP);
                System.out.println("Destination IP : " + info.destinationIP);
                System.out.println("Protocol       : " + info.protocol);

                if ("TCP".equals(info.protocol) || "UDP".equals(info.protocol)) {

                    System.out.println("Source Port     : " + info.sourcePort);
                    System.out.println("Destination Port: " + info.destinationPort);
                    System.out.println("Service         : " + info.service);
                    System.out.println("Traffic Type    : " + info.trafficType);

                    if ("TCP".equals(info.protocol)) {
                        System.out.println("TCP Flags       : " + info.tcpFlags);
                    }
                }
            }
            if (Statistics.totalPackets % 100 == 0) {

                System.out.println("\n========= DPI STATISTICS =========");

                System.out.println("Total Packets : " + Statistics.totalPackets);

                System.out.println("\nEthernet");
                System.out.println("IPv4 : " + Statistics.ipv4Packets);
                System.out.println("IPv6 : " + Statistics.ipv6Packets);
                System.out.println("ARP  : " + Statistics.arpPackets);

                System.out.println("\nProtocols");
                System.out.println("TCP : " + Statistics.tcpPackets);
                System.out.println("UDP : " + Statistics.udpPackets);

                System.out.println("\nApplications");
                System.out.println("HTTP  : " + Statistics.httpPackets);
                System.out.println("HTTPS : " + Statistics.httpsPackets);
                System.out.println("DNS   : " + Statistics.dnsPackets);
                System.out.println("SSH   : " + Statistics.sshPackets);

                System.out.println("==================================\n");
                FlowManager.printFlows();
                HostStatisticsManager.printTopTalkers();
                ReportGenerator.exportCSV();
                ReportGenerator.exportHTML();
                PDFReportGenerator.generateReport();
            }
            System.out.println("========================");
        }
    }
}