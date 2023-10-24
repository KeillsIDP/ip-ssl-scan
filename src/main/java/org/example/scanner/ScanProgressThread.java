package org.example.scanner;

import org.apache.commons.collections4.list.SetUniqueList;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ScanProgressThread extends Thread{

    private final List<ThreadedIpScan> threads;
    private final int overallCount;
    private int finishedCount;

    public ScanProgressThread(List<ThreadedIpScan> threads,int overallCount){
        this.threads = threads;
        this.overallCount = overallCount;
    }

    @Override
    public void run(){
        for (ThreadedIpScan thread : threads) {
            thread.start();
        }

        while (true) {
            finishedCount=0;
            for (ThreadedIpScan thread : threads) {
                finishedCount += thread.getScansFinishedCount();
            }

            if(isCompleted())
                break;

            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        List<String> domains = new ArrayList<String>();

        for (ThreadedIpScan thread : threads) {
            domains.addAll(thread.getDomains());
        }

        writeToFile(domains);
        domains = SetUniqueList.setUniqueList(domains);
        System.out.println(domains);
        System.out.println("Finished");
    }

    private void writeToFile(List<String> domains){
        try(FileWriter writer = new FileWriter("domains.txt", false))
        {
            for (String domain: domains) {
                writer.write(domain);
                writer.append('\n');
            }
            writer.flush();
        }
        catch(IOException e){
            System.out.println(e.getMessage());
        }
    }

    public boolean isCompleted(){
        return overallCount==finishedCount;
    }
}
