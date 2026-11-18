<<<<<<< HEAD

# ProjectCP093 – Server Log Analyzer

## Project Overview
ProjectCP093 is a simple Java-based Server Log Analyzer that reads server log records from a CSV file and generates useful analytical information.

## Features
- Total request counting
- HTTP status code analysis
- Unique IP address detection
- Server error identification
- Slow request detection
- Repeated failed login detection
- Complete analytical summary

## Technologies Used
- Java
- CSV
- VS Code
- Git and GitHub

## Project Structure
- Main.java – Main application
- LogEntry.java – Stores log records
- LogReader.java – Reads CSV data
- LogAnalyzer.java – Analyses server logs
- logs.csv – Sample dataset

## How to Run

Compile:
javac -d out src/*.java

Execute:
java -cp out Main

## Dataset
The application uses a sample CSV dataset containing server timestamps, IP addresses, HTTP methods, endpoints, status codes and response times.

## Project Purpose
This project demonstrates basic Java programming, file handling, collections and data analysis.
=======
# LogLens — Server Log Analytics Tool

## 1. Project Overview

LogLens is a Java-based, menu-driven console application that analyzes server log records. It helps identify request patterns, HTTP errors, slow endpoints, and suspicious login activity.

## 2. Objectives

- Analyze server log records stored in a CSV file.
- Count requests by HTTP status code.
- Identify the most frequent IP addresses and endpoints.
- Analyze errors by hour.
- Find endpoints with the highest average response time.
- Detect IP addresses with repeated failed login attempts.

## 3. Technologies Used

- **Programming Language:** Java
- **Data Format:** CSV
- **Development Environment:** Visual Studio Code
- **Java Libraries:** Collections Framework, File I/O, Scanner

## 4. Core Features

1. Request counts by status code.
2. Top five IP addresses and endpoints.
3. Hourly error analysis.
4. Slowest endpoints by average response time.
5. Suspicious IP detection based on failed login attempts.

## 5. Project Structure

```text
ProjectCP093/
│
├── data/
│   └── logs.csv
│
├── reports/
│   └── generated reports
│
├── src/
│   ├── Main.java
│   ├── LogEntry.java
│   ├── LogReader.java
│   ├── LogAnalyzer.java
│   ├── ReportWriter.java
│   └── SecurityAlert.java
│
├── README.md
├── TEST_CASES.md
└── .gitignore
```

## 6. How to Run

Open the terminal in the project root directory.

Compile the Java files:

```bashjavac src\Main.java src\LogEntry.java src\LogReader.java src\LogAnalyzer.java src\ReportWriter.java
```

Run the application:

```bash
java -cp src Main
```

Ensure that `data/logs.csv` exists before running the application.

## 7. Input Data

The application reads CSV records containing:

- Time
- IP address
- Endpoint
- HTTP status code
- Response time

The current dataset contains synthetic log records for testing and demonstration.

## 8. Future Enhancements

- Filter logs by a selected time window.
- Export analysis results to a report file.
- Add date-aware analysis for logs spanning multiple days.
- Improve validation and error reporting for malformed records.
>>>>>>> 9734903710dd31759b7a8a3d1328dce23da76c81
