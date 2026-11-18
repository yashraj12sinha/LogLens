
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
