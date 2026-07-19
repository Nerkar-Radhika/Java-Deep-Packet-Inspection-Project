package com.radhika.dpi.capture;

import java.util.List;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

public class InterfaceScanner {

    public static void main(String[] args) {

        try {

            List<PcapNetworkInterface> devices = Pcaps.findAllDevs();

            for (PcapNetworkInterface device : devices) {

                System.out.println("----------------------------");
                System.out.println("Name: " + device.getName());
                System.out.println("Description: " + device.getDescription());
                System.out.println("Loopback: " + device.isLoopBack());

            }

        } catch (PcapNativeException e) {

            e.printStackTrace();

        }

    }
}