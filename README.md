# ip-ssl-scan
Scan ips ssl certificates and get their domains

 <b>This project uses Javalin and Apache Http Client</b></br>
 This program get SSL certificates from ip range and find their domains.</br>
 Runs on :7000</br>

 Web-interface handles one form with two inputs:</br>
 ip adress with mask. example: 123.123.123.0/24</br>
 count of threads to use.</br>

 Program saves .txt file in project directory with all domains found.</br>
