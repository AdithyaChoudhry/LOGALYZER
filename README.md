# LOGALYZER
Analysis of Log File
-------------------------------------
Log Analysis

The Log Analysis script checks the log file for useful data like which IPs visited the most, which pages are most popular, and if there’s suspicious login activity (like too many failed logins).

-------------------------------------
How To Use

1.Put Your Log File in the script’s folder (by default, it’s looking at C:\Users\choud\PycharmProjects\pythonProject7\Sample.log).
2.Run the Script: It’ll analyze the logs and show you results.

-------------------------------------
Results in the Terminal:
It’ll show IPs with request counts, the most accessed page, and suspicious activity (e.g., failed logins)

IP Address           Request Count
192.168.1.1         25


Most Accessed Endpoint:
/home (Accessed 100 times)

Suspicious Activity Detected:
203.0.113.5         15

-------------------------------------
How It Works

1.Log Parsing: It uses regular expressions to grab key details from the log (IP, page, status code, etc.).
2.Failed Logins: It checks for failed logins (status 401 or "Invalid credentials").
3.Counting: It counts how many requests each IP made and which pages were hit the most.

---------------------------------------------------------------------------------------------------------------
Log Creator

The Log Creator makes fake log files like what you'd see in a real web server. It logs things like page visits, login attempts, and errors. It's perfect for testing.

How To Use

1.Run the Script: Just run the Log Creator, and it’ll generate a log file.
2.Customize: Change where the log file gets saved or what requests get logged if needed.

Ex: 

192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"

---------------------------------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------------------------------

How to Run It
1.Download the project files or Clone From Git
2.Run the Log Creator to generate a log.
3.Run the Log Analysis to analyze it.

