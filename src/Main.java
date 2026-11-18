
import java.io.IOException;
import java.util.ArrayList;

public class Main {

    public static void main(String[] args) {

        LogReader reader = new LogReader();
        LogAnalyzer analyzer = new LogAnalyzer();

        try {

            ArrayList<LogEntry> logs =
                    reader.readLogs("data/logs.csv");

            if (logs.isEmpty()) {
                System.out.println("No log records found.");
                return;
            }

            System.out.println("\n================================");
            System.out.println("       PROJECT CP093");
            System.out.println("     SERVER LOG ANALYZER");
            System.out.println("================================");

            int choice;

            do {

                System.out.println("\n---------- MAIN MENU ----------");
                System.out.println("1. Total Requests");
                System.out.println("2. HTTP Status Analysis");
                System.out.println("3. Unique IP Addresses");
                System.out.println("4. Server Errors");
                System.out.println("5. Slow Requests");
                System.out.println("6. Failed Login Analysis");
                System.out.println("7. Complete Summary");
                System.out.println("0. Exit");
                System.out.print("Enter your choice: ");

                choice = Integer.parseInt(
                        new java.util.Scanner(System.in).nextLine()
                );

                switch (choice) {

                    case 1:
                        System.out.println(
                                "Total Requests: "
                                + analyzer.getTotalRequests(logs)
                        );
                        break;

                    case 2:
                        System.out.println("\nHTTP Status Analysis:");
                        System.out.println("200: " +
                                analyzer.countStatusCode(logs, 200));
                        System.out.println("401: " +
                                analyzer.countStatusCode(logs, 401));
                        System.out.println("404: " +
                                analyzer.countStatusCode(logs, 404));
                        System.out.println("500: " +
                                analyzer.countStatusCode(logs, 500));
                        break;

                    case 3:
                        System.out.println(
                                "Unique IP Addresses: "
                                + analyzer.getUniqueIpCount(logs)
                        );
                        break;

                    case 4:
                        System.out.println(
                                "Server Errors: "
                                + analyzer.countServerErrors(logs)
                        );
                        break;

                    case 5:
                        System.out.println(
                                "Slow Requests: "
                                + analyzer.countSlowRequests(logs)
                        );
                        break;

                    case 6:
                        analyzer.displaySuspiciousIPs(logs);
                        break;

                    case 7:
                        System.out.println("\n====== COMPLETE SUMMARY ======");
                        System.out.println("Total Requests: " +
                                analyzer.getTotalRequests(logs));
                        System.out.println("Successful Requests: " +
                                analyzer.countStatusCode(logs, 200));
                        System.out.println("Unauthorized Requests: " +
                                analyzer.countStatusCode(logs, 401));
                        System.out.println("Not Found Requests: " +
                                analyzer.countStatusCode(logs, 404));
                        System.out.println("Server Errors: " +
                                analyzer.countServerErrors(logs));
                        System.out.println("Unique IP Addresses: " +
                                analyzer.getUniqueIpCount(logs));
                        System.out.println("Slow Requests: " +
                                analyzer.countSlowRequests(logs));

                        analyzer.displaySuspiciousIPs(logs);
                        break;

                    case 0:
                        System.out.println("Exiting ProjectCP093...");
                        break;

                    default:
                        System.out.println("Invalid choice. Try again.");
                }

            } while (choice != 0);

        } catch (IOException e) {

            System.out.println("Error reading CSV file: "
                    + e.getMessage());

        } catch (NumberFormatException e) {

            System.out.println("Please enter a valid menu number.");

        }
    }
}
