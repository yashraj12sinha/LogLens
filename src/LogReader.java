
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

public class LogReader {

    public ArrayList<LogEntry> readLogs(String filePath)
            throws IOException {

        ArrayList<LogEntry> logs = new ArrayList<>();

        BufferedReader reader =
                new BufferedReader(new FileReader(filePath));

        String line;

        // Skip the CSV header
        reader.readLine();

        // Read records one by one
        while ((line = reader.readLine()) != null) {

            String[] data = line.split(",");

            try {

                String timestamp = data[0];
                String ipAddress = data[1];
                String method = data[2];
                String endpoint = data[3];

                int statusCode = Integer.parseInt(data[4]);
                int responseTime = Integer.parseInt(data[5]);

                LogEntry entry = new LogEntry(
                    timestamp,
                    ipAddress,
                    method,
                    endpoint,
                    statusCode,
                    responseTime
                );

                logs.add(entry);

            } catch (NumberFormatException |
                     ArrayIndexOutOfBoundsException e) {

                System.out.println("Skipping invalid record: " + line);
            }
        }

        reader.close();

        return logs;
    }
}
