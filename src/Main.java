
import java.util.List;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {

        String filePath = "data/logs.csv";

        // Load log records
        List<LogEntry> logs = LogReader.readLogs(filePath);

        // Check whether logs were loaded
        if (logs == null || logs.isEmpty()) {
            System.out.println(
                "No logs loaded. Check data/logs.csv."
            );
            return;
        }

        // Display total records
        System.out.println(
            "Loaded " + logs.size() + " log records."
        );

        // Calculate HTTP error rate
        System.out.printf(
            "Error Rate: %.2f%%%n",
            LogAnalyzer.calculateErrorRate(logs)
        );

        // Calculate average response time
        System.out.printf(
            "Average Response Time: %.2f ms%n",
            LogAnalyzer.calculateAverageResponseTime(logs)
        );

        // Calculate maximum response time
        System.out.printf(
            "Maximum Response Time: %.2f ms%n",
            LogAnalyzer.calculateMaxResponseTime(logs)
        );

        Scanner scanner = new Scanner(System.in);
        int choice = 0;

        do {

            System.out.println("\n========== LOGLENS ==========");
            System.out.println("1. Count requests by status code");
            System.out.println("2. Show top five IPs and endpoints");
            System.out.println("3. Show errors per hour");
            System.out.println("4. Show slowest endpoints");
            System.out.println("5. Detect suspicious IP addresses");
            System.out.println("6. Filter logs by time window");
            System.out.println("7. Export report to a file");
            System.out.println("8. Exit");

            System.out.print("Enter your choice: ");

            // Validate menu input
            if (!scanner.hasNextInt()) {

                System.out.println(
                    "Invalid input. Enter a number from 1 to 8."
                );

                scanner.nextLine();
                continue;
            }

            choice = scanner.nextInt();
            scanner.nextLine();

            switch (choice) {

                case 1:
                    LogAnalyzer.countStatusCodes(logs);
                    break;

                case 2:
                    LogAnalyzer.showTopFive(logs);
                    break;

                case 3:
                    LogAnalyzer.showHourlyErrors(logs);
                    break;

                case 4:
                    LogAnalyzer.showSlowestEndpoints(logs);
                    break;

                case 5:
                    LogAnalyzer.detectSuspiciousIPs(logs);
                    break;

                case 6:

                    System.out.print(
                        "Enter start time (HH:mm:ss): "
                    );

                    String startTime = scanner.nextLine().trim();

                    System.out.print(
                        "Enter end time (HH:mm:ss): "
                    );

                    String endTime = scanner.nextLine().trim();

                    List<LogEntry> filteredLogs =
                        LogAnalyzer.filterByTime(
                            logs, startTime, endTime
                        );

                    if (!filteredLogs.isEmpty()) {

                        System.out.println(
                            "\n===== FILTERED LOG ANALYSIS ====="
                        );

                        System.out.println(
                            "Filtered records: " + filteredLogs.size()
                        );

                        LogAnalyzer.countStatusCodes(filteredLogs);

                        System.out.printf(
                            "Filtered Error Rate: %.2f%%%n",
                            LogAnalyzer.calculateErrorRate(filteredLogs)
                        );

                    } else {

                        System.out.println(
                            "No matching records found, "
                            + "or the time input was invalid."
                        );
                    }

                    break;

                case 7:

                    ReportWriter.exportReport(
                        logs, null, null
                    );

                    break;

                case 8:

                    System.out.println(
                        "Exiting LogLens. Goodbye!"
                    );

                    break;

                default:

                    System.out.println(
                        "Invalid choice. Please select 1 to 8."
                    );
            }

        } while (choice != 8);

        scanner.close();
    }
}
